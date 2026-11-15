import type { ServerProviderUsageLimits, ServerProviderUsageWindow } from "@t3tools/contracts";
import {
  clampPercent,
  makeUnavailableUsageLimits,
  makeUsageLimits,
} from "@t3tools/provider-core/server/usageLimits";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Clock from "effect/Clock";
import * as Digest from "effect/crypto/Digest";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Hex from "effect/encoding/Hex";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import type { PlatformError } from "effect/PlatformError";
import * as Schema from "effect/Schema";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpClientResponse from "effect/http/HttpClientResponse";

import type { AcpRegistrySettings } from "../settings.ts";

// Mirrors Kimi Code 2.x and the archived kimi-cli 1.x. Their refresh tokens are single-use,
// so a refresh whose answer is lost would sign the CLI out. T3 never refreshes or writes
// Kimi's credentials; it only reads the access token the CLI keeps fresh.

const DEFAULT_OAUTH_HOST = "https://auth.kimi.com";
const DEFAULT_BASE_URL = "https://api.kimi.com/coding/v1";
/** A token this close to expiry could lapse mid-read, so it counts as expired. */
const EXPIRY_MARGIN_SECONDS = 30;

export type KimiCli = "kimi-code" | "kimi-legacy";

/** Which Kimi CLI an ACP Registry instance runs, or undefined for other agents. */
export function kimiCliCandidates(
  settings: Pick<AcpRegistrySettings, "source" | "agentId" | "commandPath" | "commandArgs">,
): ReadonlyArray<KimiCli> | undefined {
  if (settings.source === "registry") {
    if (settings.agentId === "kimi-code") return ["kimi-code"];
    if (settings.agentId === "kimi") return ["kimi-legacy"];
    return undefined;
  }
  // Package launchers such as `npx @moonshot-ai/kimi-code acp` or `uvx kimi-cli acp`.
  if (settings.commandArgs.some((arg) => arg.startsWith("@moonshot-ai/kimi-code"))) {
    return ["kimi-code"];
  }
  if (settings.commandArgs.some((arg) => /^kimi-cli(?:[@=<>~]|$)/.test(arg))) {
    return ["kimi-legacy"];
  }
  const name = settings.commandPath
    .split(/[\\/]/)
    .at(-1)
    ?.replace(/\.(exe|cmd|bat|mjs|js)$/i, "")
    .toLowerCase();
  // A local `kimi` is either generation; the 2.x home wins when both are signed in.
  return name === "kimi" || name === "kimi-code" ? ["kimi-code", "kimi-legacy"] : undefined;
}

const QuotaEntry = Schema.Struct({
  used_ratio: Schema.optional(Schema.Union([Schema.Number, Schema.String])),
  reset_time: Schema.optional(Schema.NullOr(Schema.String)),
});
const UsagePayload = Schema.Struct({
  usages: Schema.optional(
    Schema.Struct({
      limit_5h: Schema.optional(Schema.NullOr(QuotaEntry)),
      limit_7d: Schema.optional(Schema.NullOr(QuotaEntry)),
      limit_month_total: Schema.optional(Schema.NullOr(QuotaEntry)),
      limit_month_code: Schema.optional(Schema.NullOr(QuotaEntry)),
    }),
  ),
});
const UserInfo = Schema.Struct({ user_id: Schema.NonEmptyString });
/** Only what the probe reads; the refresh token is never decoded. */
const TokenFile = Schema.Struct({
  access_token: Schema.optional(Schema.String),
  expires_at: Schema.optional(Schema.Number),
});
type TokenFile = typeof TokenFile.Type;
const decodeUsagePayload = Schema.decodeUnknownEffect(UsagePayload);
const decodeUserInfo = Schema.decodeUnknownEffect(UserInfo);
const decodeTokenFile = Schema.decodeEffect(Schema.fromJsonString(TokenFile));

const WINDOWS = [
  { key: "limit_5h", label: "5-hour", kind: "session", windowDurationMins: 5 * 60 },
  { key: "limit_7d", label: "Weekly", kind: "weekly", windowDurationMins: 7 * 24 * 60 },
  { key: "limit_month_total", label: "Monthly", kind: "monthly" },
  { key: "limit_month_code", label: "Monthly · Kimi Code", kind: "monthly" },
] as const;

/** Windows from a `GET <base_url>/usages` answer. Omitted quotas stay omitted. */
export const kimiUsageWindows = (payload: unknown) =>
  decodeUsagePayload(payload).pipe(
    Effect.map(({ usages }) => {
      const windows: ServerProviderUsageWindow[] = [];
      for (const window of WINDOWS) {
        const entry = usages?.[window.key];
        const ratio = Number(entry?.used_ratio);
        if (entry?.used_ratio === undefined || !Number.isFinite(ratio)) continue;
        const reset = entry.reset_time ? DateTime.make(entry.reset_time) : Option.none();
        windows.push({
          id: window.key,
          label: window.label,
          kind: window.kind,
          usedPercent: clampPercent(Math.round(ratio * 1e6) / 1e4),
          ...(Option.isSome(reset) ? { resetsAt: DateTime.formatIso(reset.value) } : {}),
          ...("windowDurationMins" in window
            ? { windowDurationMins: window.windowDurationMins }
            : {}),
        });
      }
      return windows;
    }),
  );

export interface KimiManagedProviderConfig {
  readonly baseUrl?: string;
  readonly oauthHost?: string;
  readonly oauthStorage?: string;
  readonly hasOAuth: boolean;
}

function tomlString(raw: string): string | undefined {
  const value = raw.trim();
  const basic = /^"((?:[^"\\]|\\.)*)"/.exec(value);
  if (basic) {
    try {
      return JSON.parse(`"${basic[1]}"`) as string;
    } catch {
      return undefined;
    }
  }
  return /^'([^']*)'/.exec(value)?.[1];
}

function tomlInlineTable(raw: string): Map<string, string> {
  const fields = new Map<string, string>();
  const body = /^\{(.*)\}\s*(?:#.*)?$/.exec(raw.trim())?.[1] ?? "";
  for (const match of body.matchAll(/([A-Za-z0-9_-]+)\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*')/g)) {
    const value = tomlString(match[2] ?? "");
    if (match[1] && value !== undefined) fields.set(match[1], value);
  }
  return fields;
}

const PROVIDER_TABLE = /^\[\s*providers\s*\.\s*(?:"managed:kimi-code"|'managed:kimi-code')\s*\]/;
const OAUTH_TABLE =
  /^\[\s*providers\s*\.\s*(?:"managed:kimi-code"|'managed:kimi-code')\s*\.\s*oauth\s*\]/;

/**
 * Reads the managed Kimi Code provider from `config.toml`. This covers the flat
 * tables and inline `oauth` table the CLI writes, not arbitrary TOML.
 */
export function readKimiManagedProviderConfig(text: string): KimiManagedProviderConfig {
  let section: "provider" | "oauth" | undefined;
  let baseUrl: string | undefined;
  let oauthHost: string | undefined;
  let oauthStorage: string | undefined;
  let hasOAuth = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("[")) {
      section = OAUTH_TABLE.test(line)
        ? "oauth"
        : PROVIDER_TABLE.test(line)
          ? "provider"
          : undefined;
      if (section === "oauth") hasOAuth = true;
      continue;
    }
    if (section === undefined) continue;
    const assignment = /^([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(line);
    if (!assignment) continue;
    const [, key, value = ""] = assignment;
    if (section === "provider" && key === "base_url") baseUrl = tomlString(value) ?? baseUrl;
    if (section === "provider" && key === "oauth") {
      hasOAuth = true;
      const table = tomlInlineTable(value);
      oauthHost = table.get("oauth_host") ?? oauthHost;
      oauthStorage = table.get("storage") ?? oauthStorage;
    }
    if (section === "oauth" && key === "oauth_host") oauthHost = tomlString(value) ?? oauthHost;
    if (section === "oauth" && key === "storage") oauthStorage = tomlString(value) ?? oauthStorage;
  }
  return {
    hasOAuth,
    ...(baseUrl ? { baseUrl } : {}),
    ...(oauthHost ? { oauthHost } : {}),
    ...(oauthStorage ? { oauthStorage } : {}),
  };
}

const trimEndpoint = (value: string) => value.trim().replace(/\/+$/, "");

/** The CLI hashes `JSON.stringify({ oauthHost, baseUrl })`; key order matters. */
const slotSeed = (oauthHost: string, baseUrl: string) => JSON.stringify({ oauthHost, baseUrl });

export interface KimiCodeAuthTarget {
  /** Credential slot: `<home>/credentials/<slot>.json`. */
  readonly slot: string;
  readonly oauthHost: string;
  readonly baseUrl: string;
}

/**
 * Kimi Code's `resolveKimiCodeRuntimeAuth`: environment overrides win over
 * `config.toml`, and each (OAuth host, API base) pair has its own credential slot.
 */
export const resolveKimiCodeAuthTarget = Effect.fn("resolveKimiCodeAuthTarget")(function* (
  config: KimiManagedProviderConfig,
  environment: NodeJS.ProcessEnv,
) {
  const envBaseUrl = environment.KIMI_CODE_BASE_URL;
  const envOAuthHost = environment.KIMI_CODE_OAUTH_HOST ?? environment.KIMI_OAUTH_HOST;
  const hasEnvOverride = envBaseUrl !== undefined || envOAuthHost !== undefined;
  const configuredBaseUrl =
    envBaseUrl !== undefined ? envBaseUrl.replace(/\/+$/, "") : config.baseUrl;
  const configuredOAuthHost = hasEnvOverride ? envOAuthHost : config.oauthHost;
  const oauthHost = trimEndpoint(configuredOAuthHost ?? DEFAULT_OAUTH_HOST);
  const baseUrl = trimEndpoint(configuredBaseUrl ?? envBaseUrl ?? DEFAULT_BASE_URL);
  if (oauthHost === DEFAULT_OAUTH_HOST && baseUrl === DEFAULT_BASE_URL) {
    return { slot: "kimi-code", oauthHost, baseUrl } satisfies KimiCodeAuthTarget;
  }
  const digest = yield* Digest.Digest;
  const hash = yield* digest
    .digest(Digest.sha256, new TextEncoder().encode(slotSeed(oauthHost, baseUrl)))
    .pipe(Effect.map(Hex.encode), Effect.orDie);
  return {
    slot: `kimi-code-env-${hash.slice(0, 16)}`,
    oauthHost,
    baseUrl,
  } satisfies KimiCodeAuthTarget;
});

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * The API base a Kimi access token may be sent to: an HTTPS URL with no user info, query, or
 * fragment, without a trailing slash. Plain HTTP is accepted only for loopback hosts and only
 * when `allowLoopbackHttp` is set, which tests do and the driver never does.
 */
export function kimiApiBaseUrl(
  raw: string,
  options: { readonly allowLoopbackHttp?: boolean } = {},
): string | undefined {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return undefined;
  }
  if (url.username || url.password || url.search || url.hash) return undefined;
  const secure =
    url.protocol === "https:" ||
    (url.protocol === "http:" &&
      options.allowLoopbackHttp === true &&
      LOOPBACK_HOSTS.has(url.hostname));
  if (!secure) return undefined;
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

type Unavailable = {
  readonly unavailable: "unsupported" | "probeFailed";
  readonly message: string;
};
const unsupported = (message: string): Unavailable => ({ unavailable: "unsupported", message });
const probeFailed = (message: string): Unavailable => ({ unavailable: "probeFailed", message });

// A sign-in problem is "unsupported", never "probeFailed": the provider keeps the last good
// reading over a failed probe, which would show limits T3 can no longer confirm as current.
const SIGN_IN = unsupported("Sign in to Kimi Code to see its limits.");
const SIGNED_OUT = unsupported(
  "Kimi's sign-in has ended. Sign in to Kimi again to see its limits.",
);
const REJECTED = unsupported(
  "Kimi rejected its stored sign-in. Use Kimi once or sign in again, then refresh provider status.",
);
const NO_EXPIRY = unsupported(
  "Kimi's stored sign-in has no expiry time. Use Kimi once, then refresh provider status.",
);
const FILE_STORAGE = unsupported("Kimi limits need Kimi Code's file-based sign-in.");
const INSECURE_ENDPOINT = unsupported("Kimi limits are read only from an HTTPS Kimi endpoint.");
const LEGACY_CUSTOM_ENDPOINT = unsupported(
  "Limits for the legacy Kimi CLI are read only from Kimi's default endpoint.",
);
const NO_LIMITS = unsupported("This Kimi endpoint does not report plan limits.");
const UNREADABLE = probeFailed("Could not read Kimi limits. Refresh provider status to retry.");

const expiredSignIn = (expiresAt: number, now: number) => {
  const at = Option.match(DateTime.make(expiresAt * 1000), {
    onNone: () => "",
    onSome: (time) => ` at ${DateTime.formatIso(time)}`,
  });
  return unsupported(
    `Kimi's sign-in ${expiresAt <= now ? "expired" : "is about to expire"}${at}. Kimi renews it while you use it: use Kimi once, then refresh provider status.`,
  );
};

interface Credentials {
  readonly accessToken: string;
  readonly baseUrl: string;
}

export interface KimiUsageProbeInput {
  readonly candidates: ReadonlyArray<KimiCli>;
  readonly environment: NodeJS.ProcessEnv;
  /** Tests only: let tokens go to `http://` loopback endpoints. */
  readonly allowLoopbackHttp?: boolean;
}

/**
 * Reads Kimi plan limits with the access token a Kimi CLI keeps on disk. The probe only reads
 * the CLI's files; an expired token is reported, not refreshed.
 */
export const makeKimiUsageProbe = Effect.fn("makeKimiUsageProbe")(function* (
  input: KimiUsageProbeInput,
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const digest = yield* Digest.Digest;
  const client = yield* HttpClient.HttpClient;
  const env = input.environment;
  const home = env.HOME || env.USERPROFILE || (yield* HostProcess.HomeDirectory);
  const endpointOptions = { allowLoopbackHttp: input.allowLoopbackHttp === true };

  const readOptional = (file: string) =>
    fs.readFileString(file).pipe(
      Effect.asSome,
      Effect.catchTags({
        PlatformError: (error) =>
          error.reason._tag === "NotFound" ? Effect.succeedNone : Effect.fail(error),
      }),
    );
  const readToken = (file: string): Effect.Effect<Option.Option<TokenFile>, PlatformError> =>
    readOptional(file).pipe(
      Effect.flatMap((text) =>
        Option.isNone(text)
          ? Effect.succeedNone
          : // The CLI treats a corrupt file as "no token stored".
            decodeTokenFile(text.value).pipe(
              Effect.asSome,
              Effect.orElseSucceed(() => Option.none<TokenFile>()),
            ),
      ),
    );

  /** The stored access token, or why it cannot be used right now. */
  const currentAccessToken = Effect.fn("KimiUsage.currentAccessToken")(function* (
    token: TokenFile,
  ) {
    // An empty access token is the CLI's tombstone for a rejected refresh token.
    if (!token.access_token) return SIGNED_OUT;
    const expiresAt = token.expires_at;
    if (expiresAt === undefined || !Number.isFinite(expiresAt)) return NO_EXPIRY;
    const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);
    if (expiresAt - now <= EXPIRY_MARGIN_SECONDS) return expiredSignIn(expiresAt, now);
    return token.access_token;
  });

  const kimiCodeCredentials = Effect.fn("KimiUsage.kimiCodeCredentials")(function* () {
    const kimiHome = env.KIMI_CODE_HOME || path.join(home, ".kimi-code");
    const config = readKimiManagedProviderConfig(
      Option.getOrElse(yield* readOptional(path.join(kimiHome, "config.toml")), () => ""),
    );
    if (config.oauthStorage !== undefined && config.oauthStorage !== "file") return FILE_STORAGE;
    const target = yield* resolveKimiCodeAuthTarget(config, env).pipe(
      Effect.provideService(Digest.Digest, digest),
    );
    const stored = yield* readToken(path.join(kimiHome, "credentials", `${target.slot}.json`));
    if (Option.isNone(stored)) return config.hasOAuth ? SIGNED_OUT : SIGN_IN;
    const accessToken = yield* currentAccessToken(stored.value);
    if (typeof accessToken !== "string") return accessToken;
    // The slot's token was issued for this base URL, but only ever leaves over HTTPS.
    const baseUrl = kimiApiBaseUrl(target.baseUrl, endpointOptions);
    if (baseUrl === undefined) return INSECURE_ENDPOINT;
    return { accessToken, baseUrl } satisfies Credentials;
  });

  /** The 1.x CLI's single credential belongs to Kimi's own endpoint, so it is never sent elsewhere. */
  const legacyCredentials = Effect.fn("KimiUsage.legacyCredentials")(function* () {
    const shareDir = env.KIMI_SHARE_DIR || path.join(home, ".kimi");
    const stored = yield* readToken(path.join(shareDir, "credentials", "kimi-code.json"));
    if (Option.isNone(stored)) return SIGN_IN;
    const accessToken = yield* currentAccessToken(stored.value);
    if (typeof accessToken !== "string") return accessToken;
    const override = env.KIMI_CODE_BASE_URL;
    if (override !== undefined && trimEndpoint(override) !== DEFAULT_BASE_URL) {
      return LEGACY_CUSTOM_ENDPOINT;
    }
    return { accessToken, baseUrl: DEFAULT_BASE_URL } satisfies Credentials;
  });

  const credentials = Effect.gen(function* () {
    let reported: Unavailable | undefined;
    for (const cli of input.candidates) {
      const result =
        cli === "kimi-code" ? yield* kimiCodeCredentials() : yield* legacyCredentials();
      if ("accessToken" in result) return result;
      // Report the first real problem; a generation that was never signed in says less.
      if (reported === undefined || reported === SIGN_IN) reported = result;
    }
    return reported ?? SIGN_IN;
  });

  const get = (credentials: Credentials, resource: string) =>
    client
      .execute(
        HttpClientRequest.get(`${credentials.baseUrl}/${resource}`).pipe(
          HttpClientRequest.acceptJson,
          HttpClientRequest.bearerToken(credentials.accessToken),
        ),
      )
      // A redirect must not carry the token to another URL; a 3xx answer fails the read.
      .pipe(Effect.provideService(FetchHttpClient.RequestInit, { redirect: "manual" }));

  const read = Effect.gen(function* () {
    const checkedAt = DateTime.formatIso(yield* DateTime.now);
    const resolved = yield* credentials;
    if ("unavailable" in resolved) {
      return makeUnavailableUsageLimits({ checkedAt, ...asLimits(resolved) });
    }
    const [usage, account] = yield* Effect.all(
      [
        get(resolved, "usages"),
        // The account ID merges one Kimi account across instances and environments.
        get(resolved, "me").pipe(
          Effect.flatMap(HttpClientResponse.filterStatusOk),
          Effect.flatMap((response) => response.json),
          Effect.flatMap(decodeUserInfo),
          Effect.flatMap((info) =>
            digest.digest(Digest.sha256, new TextEncoder().encode(`kimi-code\0${info.user_id}`)),
          ),
          Effect.map(Hex.encode),
          Effect.option,
        ),
      ],
      { concurrency: "unbounded" },
    );
    if (usage.status === 401 || usage.status === 403) {
      return makeUnavailableUsageLimits({ checkedAt, ...asLimits(REJECTED) });
    }
    if (usage.status === 404) {
      return makeUnavailableUsageLimits({ checkedAt, ...asLimits(NO_LIMITS) });
    }
    const windows = yield* HttpClientResponse.filterStatusOk(usage).pipe(
      Effect.flatMap((response) => response.json),
      Effect.flatMap(kimiUsageWindows),
    );
    if (windows.length === 0) {
      return makeUnavailableUsageLimits({
        checkedAt,
        reason: "probeFailed",
        message: "Kimi did not return usable quota information.",
      });
    }
    return {
      ...makeUsageLimits({ checkedAt, windows }),
      ...(Option.isSome(account) ? { credentialFingerprint: account.value } : {}),
    } satisfies ServerProviderUsageLimits;
  });

  return read.pipe(
    Effect.timeout("30 seconds"),
    Effect.catch(() =>
      Effect.map(DateTime.now, (now) =>
        makeUnavailableUsageLimits({
          checkedAt: DateTime.formatIso(now),
          ...asLimits(UNREADABLE),
        }),
      ),
    ),
  );
});

function asLimits(value: Unavailable) {
  return { reason: value.unavailable, message: value.message };
}
