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
  /** Where superseding events for these appraisals are published. */
  status_channel: string
  /** What to do when the status channel cannot be reached. */
  on_status_unreachable: 'fail_closed' | 'fail_open'
}

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
  /** Superseded appraisal sequences, keyed by appraisal subject. */
  superseded: Record<string, number>
  /** Is the status channel reachable? */
  statusReachable: boolean
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
  status_channel: 'https://demo.verifiedagents.ai/status/atf',
  on_status_unreachable: 'fail_closed',
}

function parseJson<T>(raw: string | undefined, fallback: T): T {
  if (!raw) return fallback
  try {
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

export function resolveConfig(env: Env): Config {
  const supersededList = parseJson<{ appraisal_subject: string; sequence: number }[]>(
    env.ATF_SUPERSEDED,
    []
  )
  const superseded: Record<string, number> = {}
  for (const entry of supersededList) {
    if (entry && typeof entry.appraisal_subject === 'string') {
      superseded[entry.appraisal_subject] = Number(entry.sequence)
    }
  }

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
    superseded,
    statusReachable: env.ATF_STATUS !== 'unreachable',
  }
}
