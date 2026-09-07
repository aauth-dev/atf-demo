// atf-demo.aauth.dev — an AAuth resource that reads an ATF grade.
//
// The relying party of the CSA Verifiable Agent Summit chain:
//
//   TRACE is the evidence. ATF is the judgment. AAuth is the delivery.
//   The relying party still decides.
//
// An agent presents an AAuth agent token, signed by its agent provider,
// carrying a `https://agentictrustframework.ai/atf` claim: a grade the
// provider vouches for, assigned by an ATF evaluator over a TRACE record.
//
//   GET /agent/echo      → 200 with what was verified and who established it
//   GET /api/summarize   → the same gate, then 401 requirement=person-token
//
// The second endpoint is the point of the demo. A Senior grade gets an agent
// considered, not admitted: the door still asks who the person is.
//
// Everything here is AAuth as written except the ATF gate in src/atf.ts and
// the policy member in the metadata document. Remove those and what is left
// is a plain agent-identity resource.

import { Hono } from 'hono'
import type { Context } from 'hono'
import { cors } from 'hono/cors'
import {
  verify as httpSigVerify,
  generateSignatureErrorHeader,
  generateAcceptSignatureHeader,
  generateAcceptSignatureSchemeHeader,
  generateAcceptSignatureAlgHeader,
} from '@hellocoop/httpsig'
import type { SignatureErrorCode } from '@hellocoop/httpsig'
import { buildAAuthHeader } from '@aauth/resource'
import { resolveConfig, ATF_POLICY, type Config } from './config'
import {
  CLOCK_TOLERANCE_SECONDS,
  buildAtfChallenge,
  revocationKey,
  runGate,
  verificationReport,
  type GatePass,
  type GateResult,
} from './atf'
import { claimedIdentity, emit, emitVerifyFailed } from './events'
import type { HonoEnv } from './types'

const app = new Hono<HonoEnv>()

// Catch every unhandled exception, emit a structured error event with
// a stack trace, and return a clean 500.
app.onError((err, c) => {
  const error = err instanceof Error ? err : new Error(String(err))
  console.error('unhandled_error', error.stack ?? String(error))
  emit(c, {
    event: 'aauth.unhandled_error',
    level: 50,
    msg: error.message,
    error_name: error.name,
    error_message: error.message,
    error_stack: error.stack,
  })
  return c.json({ error: 'internal error' }, 500)
})

// AAuth-specific response headers must be explicitly exposed so cross-origin
// JS clients can read them. Without this, fetch() drops AAuth-Requirement
// from the 401 response and the agent never sees the challenge.
app.use(
  '*',
  cors({
    origin: '*',
    exposeHeaders: [
      'AAuth-Requirement',
      'Signature-Error',
      'Accept-Signature',
      'Accept-Signature-Scheme',
      'Accept-Signature-Alg',
      'Location',
      'Retry-After',
    ],
  })
)

// ── Well-known endpoints ──
//
// No `jwks_uri` and no signing key. Per AAuth §Resource Metadata, `jwks_uri`
// is REQUIRED only of a resource that issues resource tokens or makes signed
// calls of its own. This one verifies agent signatures and answers; it issues
// nothing and signs nothing, so it publishes no keys and holds no secret.

app.get('/.well-known/aauth-resource.json', (c) => {
  const config = resolveConfig(c.env)
  return c.json({
    issuer: config.resourceUrl,
    access_mode: 'agent-token',
    name: 'ATF Demo Resource',
    description:
      'The relying party of the CSA Verifiable Agent Summit chain. It accepts an ' +
      'AAuth agent token carrying a signed ATF grade, verifies the agent provider ' +
      'and reads the grade the provider vouches for, then decides for itself. ' +
      '`GET /agent/echo` reports what it verified; `GET /api/summarize` applies the ' +
      'same gate and then challenges for a person token, because a qualifying level ' +
      'is eligibility for consideration and not permission.',
    documentation_uri: 'https://github.com/aauth-dev/atf-demo',

    // AAuth §Token Revocation: under identity-based access the agent presents
    // its agent token to the resource directly, so the agent provider has no
    // record of which resources hold it. "A resource accepting agent tokens
    // SHOULD therefore provide a revocation endpoint, and where none is
    // reached that access is bounded by the agent token lifetime alone."
    revocation_endpoint: `${config.resourceUrl}/revoke`,

    // The ATF requirement, under the namespace ATF owns. A resource's ATF
    // policy is ATF's to define; AAuth's document just carries it.
    [ATF_POLICY]: config.atf,
  })
})

app.get('/health', (c) => c.json({ status: 'ok' }))

app.get('/', (c) => {
  const config = resolveConfig(c.env)
  return c.json({
    name: 'ATF Demo Resource',
    metadata: `${config.resourceUrl}/.well-known/aauth-resource.json`,
    endpoints: {
      '/agent/echo': 'agent identity access; reports what was verified',
      '/api/summarize': 'the same gate, then a person token challenge',
    },
  })
})

// ── The gate, shared by both protected endpoints ──

/** Headers naming the signature shape this resource expects on a retry. */
function acceptSignatureHeaders(): Record<string, string> {
  return {
    'Accept-Signature': generateAcceptSignatureHeader({
      label: 'sig',
      components: ['@method', '@authority', '@path', 'signature-key'],
    }),
    'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwt']),
  }
}

/**
 * The headers every agent-token challenge carries.
 *
 * The `aauth-resource` link relation (AAuth §Resource Metadata Link Relation)
 * is load-bearing under the bare challenge: the challenge says an AAuth agent
 * token is required but not which claim it must carry, so the requirement
 * itself lives in the metadata document. An agent that arrived without having
 * discovered this resource has nothing to append `/.well-known/…` to, and the
 * relation is how it finds the document naming the profile and level.
 */
function challengeHeaders(config: Config): Record<string, string> {
  return {
    'AAuth-Requirement': buildAtfChallenge(config),
    Link: `<${config.resourceUrl}/.well-known/aauth-resource.json>; rel="aauth-resource"`,
  }
}

/**
 * Verify the HTTP message signature, then run the ATF gate.
 *
 * Returns either a pass carrying the verified token and claim, or a Response
 * already shaped for the wire.
 */
async function gate(c: Context<HonoEnv>, config: Config): Promise<GateResult | Response> {
  const url = new URL(c.req.url)

  // 1-2. RFC 9421, then the scheme. `supportedAlgorithms` is deliberately not
  //      narrowed: the summit agent provider signs Ed25519 and other agent
  //      providers sign ES256, and both must verify.
  const sigResult = await httpSigVerify({
    method: c.req.method,
    authority: url.host,
    path: url.pathname,
    query: url.search ? url.search.slice(1) : undefined,
    headers: c.req.raw.headers,
  })

  if (!sigResult.verified) {
    const noSig = !c.req.header('signature') && !c.req.header('signature-input')

    if (noSig) {
      // Nothing presented. `AAuth-Requirement` says an AAuth agent token in
      // particular is wanted; `Accept-Signature` says what shape to sign in.
      emitVerifyFailed(c, 'no_signature')
      return problem(c, 401, 'agent_token_required', 'no signature presented', {
        ...challengeHeaders(config),
        ...acceptSignatureHeaders(),
      })
    }

    // A signature was attempted and failed. The registered Signature Error
    // Code is the machine-readable carrier; the agent-token challenge rides
    // along, because whatever was wrong, a fresh agent token restarts this.
    const headers: Record<string, string> = { ...challengeHeaders(config) }
    if (sigResult.signatureError) {
      headers['Signature-Error'] = generateSignatureErrorHeader(sigResult.signatureError)
    }
    if (sigResult.acceptSignatureAlg) {
      headers['Accept-Signature-Alg'] = generateAcceptSignatureAlgHeader(
        sigResult.acceptSignatureAlg
      )
    }
    emitVerifyFailed(c, 'signature_invalid', {
      detail: sigResult.error,
      signature_error_code: sigResult.signatureError?.error,
    })
    // The body's `error` mirrors the Signature-Error header rather than
    // naming a code of its own. The header is the machine-readable carrier
    // (AAuth §Authentication Errors) and a body that disagrees with it is
    // only ever read as a contradiction.
    return problem(
      c,
      401,
      sigResult.signatureError?.error ?? 'invalid_signature',
      sigResult.error,
      headers
    )
  }

  if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
    emitVerifyFailed(c, 'wrong_key_scheme', { actual_key_type: sigResult.keyType })
    return problem(c, 401, 'unsupported_scheme', `Signature-Key scheme ${sigResult.keyType}`, {
      'Signature-Error': generateSignatureErrorHeader({ error: 'unsupported_scheme' }),
      ...challengeHeaders(config),
      'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwt']),
    })
  }

  const typ = (sigResult.jwt.header as Record<string, unknown>).typ
  return runGate(
    sigResult.jwt.raw,
    sigResult.thumbprint,
    typ,
    config,
    undefined,
    undefined,
    c.env.REVOCATIONS
  )
}

/**
 * Every error response, in one shape.
 *
 * AAuth §Error Response Format: bodies use RFC 9457 problem details with
 * `application/problem+json` and an `error` member, and receivers determine
 * how to proceed from `error`. On a 401 the `Signature-Error` header remains
 * the machine-readable carrier (§Authentication Errors) — the body never
 * contradicts it, and `error` here repeats the header's code when there is
 * one so that the two can only ever agree.
 */
function problem(
  c: Context<HonoEnv>,
  status: 400 | 401 | 403,
  error: string,
  detail?: string,
  headers: Record<string, string> = {}
): Response {
  const body: Record<string, unknown> = {
    type: 'about:blank',
    title: status === 400 ? 'Bad Request' : status === 401 ? 'Unauthorized' : 'Forbidden',
    status,
    error,
  }
  if (detail) body.detail = detail
  return c.json(body, status, { ...headers, 'Content-Type': 'application/problem+json' })
}

/** Turn a gate failure into its response. */
function refuse(
  c: Context<HonoEnv>,
  config: Config,
  result: Exclude<GateResult, GatePass>
): Response {
  if (result.kind === 'signature') {
    emitVerifyFailed(c, result.code, { detail: result.detail })
    return problem(c, 401, result.code, result.detail, {
      'Signature-Error': generateSignatureErrorHeader({
        error: result.code as SignatureErrorCode,
      }),
      ...challengeHeaders(config),
    })
  }

  if (result.kind === 'challenge') {
    // Everything the agent can fix by obtaining a better agent token. The
    // challenge names what is wanted; the body says what was wrong with what
    // arrived. One response shape for every such condition.
    emitVerifyFailed(c, result.reason, { detail: result.detail })
    return problem(
      c,
      401,
      'agent_token_insufficient',
      result.detail,
      challengeHeaders(config)
    )
  }

  if (result.kind === 'revoked') {
    // 401 with the agent-token challenge, and no Signature-Error: the
    // registry has no code for a revoked token, and `expired_jwt` — the
    // nearest — would be false. The body names it.
    emit(c, {
      event: 'aauth.atf.revoked',
      level: 40,
      msg: 'agent token was revoked by its provider',
      agent_iss: result.iss,
      agent_jti: result.jti,
    })
    return problem(
      c,
      401,
      'agent_token_revoked',
      result.detail,
      challengeHeaders(config)
    )
  }

  // A 403 denies after the signature verified: authentication succeeded and
  // authorization did not. Per AAuth §Verification such a response MUST NOT
  // carry Signature-Error, Accept-Signature-Scheme or Accept-Signature-Alg —
  // and carries no AAuth-Requirement either, because there is nothing the
  // agent can go and get.
  emit(c, {
    event: 'aauth.atf.denied',
    level: 40,
    msg: `denied: ${result.error}`,
    atf_error: result.error,
    detail: result.detail,
    ...claimedIdentity(c),
  })
  return problem(c, 403, result.error, result.detail)
}

// ── POST /revoke — AAuth §Token Revocation ──
//
// Conforms to the section as revised by spec PR #147, which settled issue
// #146. Three things there changed what this endpoint does:
//
//   1. `iss` is no longer a request parameter. "The recipient takes it from
//      the identity it verified on the signature and keys the revocation
//      under that. A caller cannot name an issuer it cannot sign for, so
//      revoking another issuer's token is not something a recipient refuses
//      — it is unreachable." The earlier `403 not_token_issuer` compared a
//      body member against the signer; there is now no body member to
//      compare, and the check is structural rather than enforced.
//
//   2. `jti` and `exp` are both REQUIRED. `exp` bounds how long the
//      recipient has to remember the revocation, which is exactly the hole
//      that made this endpoint unsizable before. There is no fallback TTL
//      any more, because there is no request without an `exp`.
//
//   3. The response is `200 OK` with an empty body, "whether or not it holds
//      a record of the token", and there is no not-found response: "a
//      recipient cannot distinguish a token it never saw from one it saw and
//      no longer holds, and an answer that varied with what it holds would
//      disclose that."
//
// ── What this endpoint can and cannot revoke ────────────────────────────
//
// The same revision names what is revocable and where, and it rules out the
// thing this endpoint was built to do:
//
//   "An agent token is revoked only at a PS, by the agent provider that
//   issued it. A resource that accepts an agent token directly under
//   identity-based access has no revocation path: the agent provider holds
//   no record of which resources an agent presents its token to, so it has
//   nothing to call. That access is bounded by the agent token's lifetime
//   alone, which is why an agent token SHOULD NOT live longer than 24
//   hours."
//
// This resource serves identity-based access. So it accepts revocations and
// enforces them — the endpoint below is a conforming implementation — but no
// conforming caller has anything to send it, because the only credential it
// accepts is an agent token and an agent token is revoked at the PS.
//
// Reaching the resource requires the four-party flow: the agent obtains a
// person token from the PS, a resource token from here, and an auth token
// from the PS, which federates to an AS. The AS is where the ATF claim on
// the agent token gets checked, and the auth token the AS issues is what
// this endpoint would then revoke, on the AS's call, when the agent
// provider revokes the agent token at the PS and the PS cascades. That is
// the flow this demo has not yet built. See `demo/resource-contract.md`.

interface RevocationRequest {
  jti?: unknown
  exp?: unknown
}

/**
 * The caller's verified identity, which is the `iss` the revocation is keyed
 * under. Taken from the signature and never from the body.
 *
 * `jwks_uri` names the signer's identity URL directly and is what the spec's
 * example uses — the caller signs with the key its own metadata publishes, so
 * the recipient resolves the `iss` of every token that party mints from the
 * signature alone. The `jwt` scheme is accepted too, where the identity is
 * the assertion's own `iss`, since that assertion's signature was verified
 * against that issuer's JWKS.
 */
function callerIdentity(sigResult: {
  keyType?: string
  jwks_uri?: { id?: string }
  jwt?: { payload?: unknown }
}): string | undefined {
  if (sigResult.keyType === 'jwks_uri') return sigResult.jwks_uri?.id
  if (sigResult.keyType === 'jwt') {
    const iss = (sigResult.jwt?.payload as Record<string, unknown> | undefined)?.iss
    return typeof iss === 'string' ? iss : undefined
  }
  // hwk is a bare key with no issuer behind it, so it identifies nobody this
  // resource could key a revocation under.
  return undefined
}

app.post('/revoke', async (c) => {
  const config = resolveConfig(c.env)
  const url = new URL(c.req.url)
  const body = await c.req.text()

  // "Recipients of revocation requests MUST verify the caller's identity via
  // HTTP Message Signatures", and "the caller's identity is established
  // before the body is examined". A request whose signature does not verify
  // is a 401 with Signature-Error.
  //
  // content-digest is required rather than merely validated when offered: a
  // signature that does not cover the body authenticates the caller and
  // authorises nothing in particular, and the body is the whole of what is
  // being asked for.
  const sigResult = await httpSigVerify(
    {
      method: c.req.method,
      authority: url.host,
      path: url.pathname,
      headers: c.req.raw.headers,
      body,
    },
    { requireContentDigest: true }
  )

  if (!sigResult.verified) {
    emitVerifyFailed(c, 'revoke_signature_invalid', {
      detail: sigResult.error,
      signature_error_code: sigResult.signatureError?.error,
    })
    const headers: Record<string, string> = { ...acceptSignatureHeaders() }
    if (sigResult.signatureError) {
      headers['Signature-Error'] = generateSignatureErrorHeader(sigResult.signatureError)
    }
    return problem(
      c,
      401,
      sigResult.signatureError?.error ?? 'invalid_signature',
      sigResult.error,
      headers
    )
  }

  const iss = callerIdentity(sigResult)
  if (!iss) {
    return problem(
      c,
      403,
      'unsupported_iss',
      `a signature under the ${String(sigResult.keyType)} scheme names no issuer this ` +
        `resource could key a revocation under`
    )
  }

  let request: RevocationRequest
  try {
    request = JSON.parse(body) as RevocationRequest
  } catch {
    return problem(c, 400, 'invalid_request', 'body is not valid JSON')
  }

  // Both REQUIRED. A missing or malformed jti or exp is invalid_request.
  const jti = typeof request.jti === 'string' && request.jti ? request.jti : undefined
  const exp = typeof request.exp === 'number' ? request.exp : undefined
  if (!jti || exp === undefined) {
    return problem(c, 400, 'invalid_request', 'jti and exp are both REQUIRED')
  }

  const now = Math.floor(Date.now() / 1000)

  // "A recipient MAY reject a revocation whose exp is further in the future
  // than the longest lifetime it accepts for any token, since it would refuse
  // such a token on presentation anyway." The longest this resource accepts
  // is an agent token's 24 hours (§Agent Tokens: SHOULD NOT exceed).
  if (exp > now + config.maxTokenLifetimeSeconds) {
    return problem(
      c,
      400,
      'invalid_request',
      `exp is further ahead than the longest token lifetime this resource accepts ` +
        `(${config.maxTokenLifetimeSeconds}s); such a token would be refused on presentation`
    )
  }

  const ttl = exp + CLOCK_TOLERANCE_SECONDS - now
  if (ttl > 0) {
    // KV's minimum expiration TTL is 60 seconds. Past exp plus skew the token
    // is refused on expiry alone and the entry is dead weight, which is the
    // discard rule the section states.
    await c.env.REVOCATIONS.put(
      revocationKey(iss, jti),
      JSON.stringify({ iss, jti, exp, revoked_at: now }),
      { expirationTtl: Math.max(60, Math.ceil(ttl)) }
    )
  }

  emit(c, {
    event: 'aauth.revoke.accepted',
    msg: 'revocation recorded',
    // The verified signer, which is the namespace the jti is keyed under.
    token_iss: iss,
    token_jti: jti,
    token_exp: exp,
    // False when the token had already expired: nothing to store, and the
    // answer is 200 either way.
    stored: ttl > 0,
  })

  // "200 OK with an empty body, once the recipient has recorded the
  // revocation, whether or not it holds a record of the token." This resource
  // verifies statelessly and keeps nothing, so it never holds one — and
  // answers exactly as it would if it did, because a response that varied
  // with what it holds would disclose that.
  return c.body(null, 200)
})

// ── GET /agent/echo — agent identity access ──

app.get('/agent/echo', async (c) => {
  const config = resolveConfig(c.env)
  const result = await gate(c, config)
  if (result instanceof Response) return result
  if (result.kind !== 'pass') return refuse(c, config, result)

  emit(c, {
    event: 'aauth.atf.verified',
    msg: 'agent token and ATF claim accepted',
    agent_iss: result.token.iss,
    agent_sub: result.token.sub,
    agent_jti: result.token.jti,
    agent_exp: result.token.exp,
    atf_level: String(result.atf.level),
    atf_profile: String(result.atf.profile),
    // The whole claim, so a 200 can be reconciled against the appraisal it
    // rests on without holding the token. `appraisal_issuer` and `sequence`
    // are the two that matter for that and were both missing before.
    atf_appraisal_id: String(result.atf.appraisal_id),
    atf_appraisal_issuer: String(result.atf.appraisal_issuer),
    atf_appraisal_exp: result.atf.exp,
    atf_sequence: result.atf.sequence,
    atf_appraisal_subject: String(result.atf.appraisal_subject),
    atf_workload_id: String(result.atf.workload_id),
    atf_appraisal_hash: String(result.atf.appraisal_hash),
    atf_evidence_hash: String(result.atf.evidence_hash),
    atf_binding_status_asserted: result.atf.binding_status,
  })

  return c.json(verificationReport(result, config))
})

// ── GET /api/summarize — the same gate, then the person ──

app.get('/api/summarize', async (c) => {
  const config = resolveConfig(c.env)
  const result = await gate(c, config)
  if (result instanceof Response) return result
  if (result.kind !== 'pass') return refuse(c, config, result)

  // The grade cleared the bar. That established eligibility for
  // consideration, and nothing else: this resource still needs to know which
  // person the agent is acting for before it will serve anything.
  emit(c, {
    event: 'aauth.atf.eligible',
    msg: 'ATF gate passed; challenging for a person token',
    agent_iss: result.token.iss,
    agent_sub: result.token.sub,
    agent_jti: result.token.jti,
    atf_level: String(result.atf.level),
    atf_profile: String(result.atf.profile),
    atf_appraisal_issuer: String(result.atf.appraisal_issuer),
  })

  return problem(
    c,
    401,
    'person_token_required',
    `ATF ${String(result.atf.level)} under ${String(result.atf.profile)} was accepted. ` +
      'A qualifying level is eligibility for consideration, not permission. ' +
      'Present a person token for this resource.',
    { 'AAuth-Requirement': buildAAuthHeader('person-token') }
  )
})

export default app
