import type { Env } from './types'

/** The ATF policy this resource applies, published in its metadata document
 *  under the `https://agentictrustframework.ai/policy` member. */
export interface AtfPolicy {
  /** Accepted `profile` values of the ATF claim. */
  profiles: string[]
  /** Lowest level that clears the gate. */
  minimum_level: string
  /** Accepted `appraisal_issuer` values. */
  evaluators: string[]
}

// ── Why there is no status_channel here ──────────────────────────────────
//
// Earlier versions published `status_channel` and `on_status_unreachable` in
// this member, and the gate had a check that consulted them. Both are gone.
//
// The channel is the evaluator's, and the evaluator already names it. Josh's
// profile requires an ATF appraisal to carry
//
//   "status": { "channel": "…", "on_unreachable": "fail_closed" }
//
// inside the signed document, next to `sequence` and `supersedes`. A resource
// republishing that value in its own metadata asserts, unsigned and by hand,
// something the evaluator asserts under signature. Two places to state one
// fact is one place for it to be wrong, and the copy here was wrong: it named
// a host that does not resolve, beside a fail-closed promise the code did not
// keep, because `statusReachable` read a config flag rather than the network.
//
// Withdrawal is now AAuth's revocation endpoint (§Token Revocation). The
// agent provider watches the evaluator's feed, and when a grade is pulled it
// calls POST /revoke here with the agent token's `(iss, jti)`. Push, not
// poll: no evaluator in the request path, and no fail-open/fail-closed
// question, because there is nothing to fail to reach.

export interface Config {
  /** This resource's identity as published and linked. In production an HTTPS
   *  server identifier; in local dev an http://localhost origin. */
  resourceUrl: string
  /**
   * The identifier used as the audience when verifying a presented token.
   *
   * AAuth §Server Identifiers requires an HTTPS URL, and `verifyToken` refuses
   * anything else — so a local dev origin can never be one. This is `ORIGIN`
   * (always HTTPS) rather than `RESOURCE_URL`, which dev overrides to
   * localhost. Nothing is weakened by the split: an agent token carries no
   * `aud`, so for agent identity access this value is never compared against
   * anything. It exists to satisfy the guard.
   */
  audience: string
  /** Agent provider issuers this resource accepts an agent token from. */
  agentProviders: string[]
  atf: AtfPolicy
  /** Dev-only JWKS override, keyed by agent provider issuer. */
  agentProviderJwks: Record<string, { keys: JsonWebKey[] }>
  /** Which carrier the 401 challenge uses for the ATF requirement. */
  challengeCarrier: 'bare' | 'params'
  /**
   * The longest token lifetime this resource will entertain, in seconds.
   *
   * AAuth §Token Revocation: "A recipient MAY reject a revocation whose `exp`
   * is further in the future than the longest lifetime it accepts for any
   * token, since it would refuse such a token on presentation anyway." The
   * longest this resource accepts is an agent token's, which §Agent Tokens
   * says SHOULD NOT exceed 24 hours.
   */
  maxTokenLifetimeSeconds: number
}

export const ATF_CLAIM = 'https://agentictrustframework.ai/atf'
export const ATF_POLICY = 'https://agentictrustframework.ai/policy'

/**
 * The ATF level vocabulary of csa-atf 0.9.1: ascending and cumulative, so a
 * level clears the gate when its index is at or above the minimum's. An
 * unknown value is not ranked and never clears — the profile rejects unknown
 * levels as no claim rather than guessing where they sit.
 */
export const ATF_LEVELS = ['intern', 'junior', 'senior', 'principal'] as const

export function levelMeets(presented: string, minimum: string): boolean {
  const have = ATF_LEVELS.indexOf(presented as (typeof ATF_LEVELS)[number])
  const need = ATF_LEVELS.indexOf(minimum as (typeof ATF_LEVELS)[number])
  if (have < 0 || need < 0) return false
  return have >= need
}

const DEFAULT_POLICY: AtfPolicy = {
  profiles: ['csa-atf:0.9.1'],
  minimum_level: 'senior',
  evaluators: ['https://demo.verifiedagents.ai'],
}

function parseJson<T>(raw: string | undefined, fallback: T): T {
  if (!raw) return fallback
  try {
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

/** 24 hours — the ceiling AAuth §Agent Tokens puts on an agent token. */
export const MAX_TOKEN_LIFETIME_SECONDS = 86_400

export function resolveConfig(env: Env): Config {
  const origin = env.ORIGIN ?? 'https://atf-demo.aauth.dev'
  return {
    resourceUrl: env.RESOURCE_URL ?? origin,
    audience: origin,
    agentProviders: (env.AGENT_PROVIDERS ?? 'https://verifiable-agent-summit-provider.vercel.app')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    atf: DEFAULT_POLICY,
    agentProviderJwks: parseJson(env.AGENT_PROVIDER_JWKS, {}),
    challengeCarrier: env.ATF_CHALLENGE_CARRIER === 'params' ? 'params' : 'bare',
    maxTokenLifetimeSeconds:
      Number(env.MAX_TOKEN_LIFETIME_SECONDS) > 0
        ? Number(env.MAX_TOKEN_LIFETIME_SECONDS)
        : MAX_TOKEN_LIFETIME_SECONDS,
  }
}
