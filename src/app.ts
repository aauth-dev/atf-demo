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
  buildAtfChallenge,
  runGate,
  verificationReport,
  type GatePass,
  type GateResult,
} from './atf'
import { emit, emitVerifyFailed } from './events'
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
  return runGate(sigResult.jwt.raw, sigResult.thumbprint, typ, config)
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
  status: 401 | 403,
  error: string,
  detail?: string,
  headers: Record<string, string> = {}
): Response {
  const body: Record<string, unknown> = {
    type: 'about:blank',
    title: status === 401 ? 'Unauthorized' : 'Forbidden',
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
  })
  return problem(c, 403, result.error, result.detail)
}

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
    atf_level: String(result.atf.level),
    atf_profile: String(result.atf.profile),
    appraisal_id: String(result.atf.appraisal_id),
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
    agent_sub: result.token.sub,
    atf_level: String(result.atf.level),
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
