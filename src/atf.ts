// The ATF gate.
//
// Everything in this file is the ATF extension. Nothing else in this resource
// departs from AAuth: the signature verification, the token verification, the
// `Signature-Error` codes, the `AAuth-Requirement` challenges and the
// problem+json error format are all the protocol as written. What is new here
// is (a) reading the `https://agentictrustframework.ai/atf` claim from the
// agent token, (b) the `https://agentictrustframework.ai/policy` member this
// resource publishes in its metadata, and (c) one `error` value in a 403
// body, which AAuth leaves to the resource to define.
//
// ── What this resource does and does not verify ────────────────────────────
//
// It verifies the agent provider's signature over the agent token, and reads
// the grade the provider vouches for. It does NOT verify the ATF evaluator's
// signature over the appraisal — the claim carries `appraisal_hash`, a digest
// of the complete signed appraisal, but no way to resolve the document behind
// it. So the grade is the AP's assertion, held on the AP's authority, exactly
// as `sub` and `cnf` are. The 200 body says so in words, and reports the
// provider's own `binding_status` beside what this resource established,
// attributed to whichever party said it.
//
// The digests travel anyway. They cost nothing, and anyone who obtains the
// appraisal or the TRACE record out of band can bind it to this token.

import {
  Token,
  serializeDictionary,
  type Dictionary,
  type Parameters,
} from '@hellocoop/httpsig'
import { AAuthTokenError, TOKEN_TYP, buildAAuthHeader, verifyToken } from '@aauth/resource'
import type { VerifiedAgentToken } from '@aauth/resource'
import { ATF_CLAIM, levelMeets, type Config } from './config'

/** The ATF claim as the summit agent provider mints it. Every member is the
 *  AP's assertion; none of it is verified against the evaluator here. */
export interface AtfClaim {
  profile?: unknown
  level?: unknown
  exp?: unknown
  sequence?: unknown
  appraisal_id?: unknown
  appraisal_issuer?: unknown
  appraisal_hash?: unknown
  evidence_hash?: unknown
  appraisal_subject?: unknown
  workload_id?: unknown
  binding_status?: unknown
}

/** A failure the agent can fix by obtaining a better agent token: 401 with an
 *  `AAuth-Requirement: requirement=agent-token` challenge. */
export interface ChallengeFailure {
  kind: 'challenge'
  /** Log/diagnostic reason. Not a wire value. */
  reason: string
  detail: string
}

/** A failure no fresh token repairs: 403 with problem+json. */
export interface DenyFailure {
  kind: 'deny'
  /** The `error` member of the problem+json body. */
  error: 'atf_subject_mismatch'
  detail: string
}

/** A signature- or token-layer failure: 401 with a registered `Signature-Error`. */
export interface SignatureFailure {
  kind: 'signature'
  /** A registered Signature Error Code. */
  code: string
  detail: string
}

/**
 * The agent provider withdrew this token: a revocation naming its
 * `(iss, jti)` reached POST /revoke and has not yet expired.
 *
 * 401, not 403. The signature verified and the claim was coherent, but the
 * credential is no longer good — the same shape of condition as expiry, and
 * the same remedy: go and get another agent token. A 403 would say there is
 * nothing to go and get, which is false unless the provider also refuses to
 * issue, and that is the provider's decision to report, not this resource's
 * to guess.
 *
 * The body's `error` is `agent_token_revoked`, this resource's own name. The
 * Signature Error Code registry in draft-hardt-httpbis-signature-key has no
 * value for a revoked token — `expired_jwt` is the nearest and it is not
 * true — so no `Signature-Error` header is sent. The `AAuth-Requirement`
 * challenge carries the actionable part.
 */
export interface RevokedFailure {
  kind: 'revoked'
  iss: string
  jti: string
  detail: string
}

export interface GatePass {
  kind: 'pass'
  token: VerifiedAgentToken
  atf: AtfClaim
}

export type GateResult =
  | GatePass
  | ChallengeFailure
  | DenyFailure
  | SignatureFailure
  | RevokedFailure

/** Key under which a revocation for `(iss, jti)` is stored.
 *
 *  AAuth §Token Revocation: a `jti` is unique only within its issuer's
 *  namespace, and recipients maintaining revocation state MUST key it by the
 *  pair. NUL separates the two so no `iss`/`jti` split can collide with
 *  another — a character neither an HTTPS server identifier nor a JWT
 *  identifier can contain. */
export function revocationKey(iss: string, jti: string): string {
  return `revoked:${iss}\u0000${jti}`
}

/** Is this token's `(iss, jti)` on the revocation list? */
export async function isRevoked(
  store: KVNamespace,
  iss: string,
  jti: string | undefined
): Promise<boolean> {
  // A token with no `jti` cannot be revoked by `(iss, jti)` and cannot be
  // looked up either. AAuth lists `jti` as REQUIRED on an agent token, so
  // this is a malformed token that got past the token layer rather than a
  // case to handle; it is reported as not revoked and refused elsewhere.
  if (!jti) return false
  return (await store.get(revocationKey(iss, jti))) !== null
}

/**
 * Build the `AAuth-Requirement` value for the agent-token challenge.
 *
 * ── Which carrier states the ATF requirement? ──────────────────────────────
 *
 * `bare` is what this resource ships. It emits exactly what AAuth -11
 * §Agent Token Required specifies:
 *
 *     AAuth-Requirement: requirement=agent-token
 *
 * The agent learns which profile and level are wanted by reading this
 * resource's metadata document, where the policy is published under
 * `https://agentictrustframework.ai/policy`. Every challenge carries a
 * `Link: …; rel="aauth-resource"` so an agent that arrived without discovery
 * can find that document. Costs one extra round trip on a first encounter and
 * changes nothing in the spec.
 *
 * `params` is the alternative, kept behind the config switch and NOT shipped:
 *
 *     AAuth-Requirement: requirement=agent-token;atf-profile="csa-atf:0.9.1";atf-level="senior"
 *
 * One round trip, and the challenge is self-describing. Two problems. First,
 * §Agent Token Required says of this requirement: "The header carries no
 * additional parameters: the agent already holds its agent token and need only
 * present it." Emitting parameters contradicts that sentence. Second, and
 * worse, it is framework-specific: every trust framework that wants to be
 * named in a challenge would mint its own parameter pair.
 *
 * The general problem — `requirement=agent-token` cannot say which claim the
 * agent token must carry — is filed as
 * https://github.com/dickhardt/AAuth/issues/145. The proposal there is a
 * single `agent-claims` parameter carrying a space-delimited String of claim
 * URIs:
 *
 *     AAuth-Requirement: requirement=agent-token;agent-claims="https://agentictrustframework.ai/atf"
 *
 * A String rather than an Inner List because RFC 8941 parameter values are
 * bare items, and named `agent-claims` rather than `claims` because `claims`
 * is already a `requirement` value. That is not spec'd yet, so no carrier for
 * it is implemented here. If #145 lands, this function grows one branch and
 * the config constant one value.
 *
 * `@aauth/resource`'s `buildAAuthHeader` types `agent-token` as a
 * `SimpleRequirement` that takes no parameters, which is why `params` builds
 * the Dictionary directly. It uses the RFC 8941 serializer the httpsig
 * package already carries — hand-rolled 8941 fails on quoting every time.
 */
export function buildAtfChallenge(config: Config): string {
  if (config.challengeCarrier === 'bare') {
    return buildAAuthHeader('agent-token')
  }

  const params: Parameters = new Map()
  params.set('atf-profile', config.atf.profiles[0])
  params.set('atf-level', config.atf.minimum_level)
  const dict: Dictionary = new Map()
  dict.set('requirement', [new Token('agent-token'), params])
  return serializeDictionary(dict)
}

/**
 * A `fetch` that serves key discovery for agent providers named in the
 * dev-only `AGENT_PROVIDER_JWKS` override, and falls through to the network
 * for everything else. Absent the override this is the global fetch and
 * discovery works normally.
 */
export function discoveryFetch(config: Config): typeof fetch {
  const overrides = config.agentProviderJwks
  if (Object.keys(overrides).length === 0) return fetch

  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const href =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(href)
    const jwks = overrides[url.origin]
    if (jwks) {
      // Serve both legs of `{iss}/.well-known/{dwk}` discovery: the metadata
      // document, and the JWKS its `jwks_uri` points at.
      if (url.pathname.startsWith('/.well-known/') && url.pathname.endsWith('.json')) {
        if (url.pathname === '/.well-known/jwks.json') {
          return Response.json(jwks)
        }
        return Response.json({
          issuer: url.origin,
          jwks_uri: `${url.origin}/.well-known/jwks.json`,
        })
      }
    }
    return fetch(input as RequestInfo, init)
  }) as typeof fetch
}

/** Seconds of clock skew tolerated on expiry, matching `verifyToken`'s default. */
export const CLOCK_TOLERANCE_SECONDS = 60

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

/**
 * Map an `AAuthTokenError.code` onto the Signature Error Code registry
 * (draft-hardt-httpbis-signature-key §6.2), which is what goes on the wire.
 *
 * The registry is finer-grained than the package's codes in one place:
 * `unknown_key` names "key not found at jwks_uri", but `@aauth/resource`
 * reports that as the generic `invalid_agent_token` along with a bad `iss`,
 * an alg disagreement and a failed signature. The package documents that
 * callers MUST branch on `code` and never on `message`, so there is no
 * supported way to separate them. A missing `kid` therefore reports as
 * `invalid_jwt` — true, but less specific than the registry allows.
 */
function signatureErrorFor(code: string): string {
  switch (code) {
    case 'token_expired':
      return 'expired_jwt'
    case 'key_binding_failed':
      return 'invalid_signature'
    default:
      return 'invalid_jwt'
  }
}

/**
 * Run the gate over an already signature-verified agent token JWT.
 *
 * Check order is load-bearing:
 *
 *  1-4  are the token layer: `verifyToken` proves `typ`, structure, expiry,
 *       the `cnf` binding to the HTTP signing key, and the AP's signature
 *       against `{iss}/.well-known/{dwk}`.
 *  5-8  establish that this claim is one this resource will read at all: a
 *       trusted provider, a claim present, a known profile, a named evaluator.
 *       All fixable by presenting a different token, so all 401 challenges.
 *  9    is the claim's internal consistency. The AP signed one token carrying
 *       both `sub` and the appraisal's subject; if they disagree the AP has
 *       contradicted itself, and no policy judgment applied to an incoherent
 *       claim means anything. Checked before policy for that reason, and it is
 *       a 403 because a fresh token from the same AP would carry the same
 *       contradiction.
 *  10-11 are policy on the claim as presented — freshness and level. Pure
 *       functions of the token, needing no external state, so they run before
 *       anything that consults the status channel. Both fixable: 401.
 *  12   is currency: whether the agent provider has withdrawn this token
 *       through POST /revoke. Last, because it is the only check that reads
 *       storage — everything above is a pure function of the token, and a
 *       token that fails one of those never costs a KV lookup. 401, because
 *       a revoked token is repaired the same way an expired one is.
 */
export async function runGate(
  jwtRaw: string,
  thumbprint: string,
  typ: unknown,
  config: Config,
  now: number = Math.floor(Date.now() / 1000),
  clockToleranceSeconds = CLOCK_TOLERANCE_SECONDS,
  revocations?: KVNamespace
): Promise<GateResult> {
  // 3. The right kind of token. A person or auth token here is not a failure
  //    of this endpoint's contract so much as the wrong flow entirely.
  if (typ !== TOKEN_TYP.agent) {
    return {
      kind: 'challenge',
      reason: 'not_an_agent_token',
      detail: `this endpoint serves agent identity access; cannot use a ${String(typ)}`,
    }
  }

  // 4. Token layer. In practice most of this has already happened: httpsig's
  //    `verify` under scheme=jwt resolves the signing key from the token's
  //    `cnf`, so a malformed or expired token dies there with a registered
  //    Signature Error Code before reaching here. This runs the checks the
  //    signature layer does not: `typ`, required claims, and the AP signature
  //    against `{iss}/.well-known/{dwk}`.
  let token: VerifiedAgentToken
  try {
    const verified = await verifyToken({
      jwt: jwtRaw,
      httpSignatureThumbprint: thumbprint,
      resource: config.audience,
      accept: ['agent'],
      fetch: discoveryFetch(config),
      clockToleranceSeconds,
      now,
    })
    if (verified.type !== 'agent') throw new Error('unreachable: accept was ["agent"]')
    token = verified
  } catch (err) {
    if (err instanceof AAuthTokenError) {
      return { kind: 'signature', code: signatureErrorFor(err.code), detail: err.message }
    }
    throw err
  }

  // 5. A provider this resource trusts.
  if (!config.agentProviders.includes(token.iss)) {
    return {
      kind: 'challenge',
      reason: 'untrusted_agent_provider',
      detail: `agent token iss "${token.iss}" is not an agent provider this resource accepts`,
    }
  }

  // 6. The claim is present.
  const raw = token.claims[ATF_CLAIM]
  if (!raw || typeof raw !== 'object') {
    return {
      kind: 'challenge',
      reason: 'atf_claim_missing',
      detail: `agent token carries no ${ATF_CLAIM} claim`,
    }
  }
  const atf = raw as AtfClaim

  // 7. A profile this resource reads.
  const profile = str(atf.profile)
  if (!profile || !config.atf.profiles.includes(profile)) {
    return {
      kind: 'challenge',
      reason: 'atf_profile_unsupported',
      detail: `ATF profile "${String(atf.profile)}" is not one this resource accepts`,
    }
  }

  // 8. An evaluator this resource named.
  const evaluator = str(atf.appraisal_issuer)
  if (!evaluator || !config.atf.evaluators.includes(evaluator)) {
    return {
      kind: 'challenge',
      reason: 'atf_evaluator_untrusted',
      detail: `appraisal issuer "${String(atf.appraisal_issuer)}" is not an evaluator this resource accepts`,
    }
  }

  // 9. The claim agrees with the token that carries it. `workload_id` is the
  //    TRACE subject the evaluator appraised, `appraisal_subject` the subject
  //    it named; the AP asserts both name the principal `sub` identifies. This
  //    is a proposed binding (interface contract, D-05), not a settled rule —
  //    what is checked here is only that the AP did not contradict itself.
  const appraisalSubject = str(atf.appraisal_subject)
  const workloadId = str(atf.workload_id)
  if (!appraisalSubject || !workloadId || appraisalSubject !== workloadId) {
    return {
      kind: 'deny',
      error: 'atf_subject_mismatch',
      detail:
        `the claim's appraisal_subject (${String(atf.appraisal_subject)}) and ` +
        `workload_id (${String(atf.workload_id)}) do not name the same subject`,
    }
  }

  // 10. The appraisal has not lapsed. Distinct from the token's own `exp`: the
  //     summit AP sets token exp to min(now + ttl, appraisal.exp) so the two
  //     coincide, but nothing requires an AP to do that, and a token outliving
  //     the evidence behind it is exactly what must not be honored.
  //
  //     The same clock tolerance the token layer applies is applied here. It
  //     has to be the same number: with zero tolerance here and 60 seconds
  //     there, a token in that 60-second window is refused by this check
  //     rather than as `expired_jwt`, so the same condition reports under two
  //     different codes depending on how fast the caller was. Skew tolerance
  //     exists so an honest client is not punished for clock drift, and that
  //     applies to the appraisal's expiry exactly as it does to the token's.
  const atfExp = typeof atf.exp === 'number' ? atf.exp : undefined
  if (atfExp === undefined || atfExp < now - clockToleranceSeconds) {
    return {
      kind: 'challenge',
      reason: 'atf_appraisal_stale',
      detail: `the appraisal expired at ${String(atf.exp)}; it is now ${now}`,
    }
  }

  // 11. The grade clears the bar.
  const level = str(atf.level)
  if (!level || !levelMeets(level, config.atf.minimum_level)) {
    return {
      kind: 'challenge',
      reason: 'atf_level_insufficient',
      detail: `level "${String(atf.level)}" is below this resource's minimum of "${config.atf.minimum_level}"`,
    }
  }

  // 12. Currency: has this token been withdrawn?
  //
  //      Two checks used to sit here. One asked whether the evaluator's
  //      status channel was reachable, and one whether a superseding event
  //      outranked this appraisal's `sequence`. Neither did what it said:
  //      both read a Worker environment variable, so in production one was
  //      permanently "reachable" and the other permanently empty, and no
  //      request could fail either. They existed so tests could force a 403.
  //
  //      What replaces them is push. The agent provider watches the
  //      evaluator's feed; when a grade is withdrawn it calls POST /revoke
  //      here with the agent token's `(iss, jti)`, and the token stops
  //      working on the next request. No evaluator in the request path, no
  //      poll, and no fail-open/fail-closed question, because there is
  //      nothing to fail to reach.
  //
  //      Last of the claim checks, because it is the only one that touches
  //      storage. Everything above is a pure function of the token.
  if (revocations && (await isRevoked(revocations, token.iss, token.jti))) {
    return {
      kind: 'revoked',
      iss: token.iss,
      jti: token.jti as string,
      detail:
        `agent token ${token.jti} from ${token.iss} was revoked by its ` +
        `agent provider; obtain a new agent token`,
    }
  }

  return { kind: 'pass', token, atf }
}

/** The 200 body: what was verified, and who established each fact. */
export function verificationReport(pass: GatePass, config: Config) {
  const { token, atf } = pass
  return {
    verified: true,
    agent_token: {
      iss: token.iss,
      sub: token.sub,
      jti: token.jti,
      iat: token.iat,
      exp: token.exp,
      established_by: 'the agent provider, whose signature this resource verified',
    },
    atf: {
      profile: atf.profile,
      level: atf.level,
      exp: atf.exp,
      sequence: atf.sequence,
      appraisal_id: atf.appraisal_id,
      appraisal_issuer: atf.appraisal_issuer,
      appraisal_hash: atf.appraisal_hash,
      evidence_hash: atf.evidence_hash,
      appraisal_subject: atf.appraisal_subject,
      workload_id: atf.workload_id,
      established_by:
        'the ATF evaluator named in appraisal_issuer, as asserted by the agent provider',
    },
    // Two statements, by two parties, about the same binding — reported
    // separately because they are not the same claim and collapsing them
    // loses one. `asserted_by_agent_provider` is the claim's own
    // `binding_status` verbatim: the provider grading its own binding, which
    // it currently labels a proposal. `established_by_this_resource` is what
    // this resource actually did, which is take the provider's word for it.
    // An earlier version reported only the second under the bare name
    // `binding_status`, which read as though it were the value in the token.
    binding: {
      asserted_by_agent_provider: atf.binding_status,
      established_by_this_resource: 'ap-asserted',
      means:
        'the agent provider signed one token carrying sub, appraisal_subject and workload_id, and this resource checked that appraisal_subject and workload_id do not contradict each other. It did not establish that an aauth: identifier and a spiffe: identifier name the same principal — nothing in AAuth or TRACE says who asserts that (interface contract, D-05).',
    },
    policy_applied: {
      profiles: config.atf.profiles,
      minimum_level: config.atf.minimum_level,
      evaluators: config.atf.evaluators,
    },
    limits: [
      'This resource verified the agent provider’s signature over the agent token. It did not verify the ATF evaluator’s signature: the claim carries appraisal_hash, a digest of the complete signed appraisal, but no way to resolve the document behind it.',
      'The grade is therefore the agent provider’s assertion, held on the agent provider’s authority — as sub and cnf are. It is not proof that the named evaluator issued it.',
      'appraisal_hash and evidence_hash are commitments. Anyone holding the appraisal or the TRACE record can bind it to this token; this resource holds neither.',
      'The subject binding is a proposal (interface contract, D-05). What was checked is that the agent provider did not contradict itself, not that an AAuth identifier and a TRACE subject are the same principal.',
      'A qualifying level is eligibility for consideration. It is not permission, and it is not a safety claim.',
    ],
  }
}
