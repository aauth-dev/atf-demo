// The ATF gate: the four interop cases, the three refusals no fresh token
// repairs, and the two endpoints' contracts.

import { beforeAll, describe, expect, it } from 'vitest'
import { SELF, createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test'
import { fetch as httpsigFetch } from '@hellocoop/httpsig'
import app from '../src/app'
import { clearMetadataCache } from '@aauth/resource'
import { parseRequirementHeader } from '@aauth/protocol'
import {
  AP,
  ATF_CLAIM,
  OTHER_AP,
  RESOURCE,
  SUBJECT,
  atfClaim,
  generateEd25519,
  installMockFetch,
  mintAgentToken,
  mockAgentProvider,
  now,
  signedGet,
  tamper,
  type TestKey,
} from './helpers'

let apKey: TestKey
let otherApKey: TestKey
let agentKey: TestKey

beforeAll(async () => {
  installMockFetch()
  ;[apKey, otherApKey, agentKey] = await Promise.all([
    generateEd25519(),
    generateEd25519(),
    generateEd25519(),
  ])
  mockAgentProvider(AP, apKey)
  mockAgentProvider(OTHER_AP, otherApKey)
  clearMetadataCache()
})

/** Assert a 401 carrying the bare agent-token challenge and the metadata link. */
async function expectChallenge(res: Response) {
  expect(res.status).toBe(401)
  const requirement = res.headers.get('AAuth-Requirement')
  expect(requirement).toBe('requirement=agent-token')
  expect(parseRequirementHeader(requirement!).requirement).toBe('agent-token')
  // Under the bare challenge the metadata document carries the requirement,
  // so an agent that failed must be able to find it.
  expect(res.headers.get('Link')).toBe(
    `<${RESOURCE}/.well-known/aauth-resource.json>; rel="aauth-resource"`
  )
  return (await res.json()) as Record<string, unknown>
}

/** Assert a 403 problem+json carrying `error`, and none of the 401-only headers. */
async function expectDeny(res: Response, error: string) {
  expect(res.status).toBe(403)
  expect(res.headers.get('Content-Type')).toContain('application/problem+json')
  // AAuth §Verification: a 403 denies after the signature verified, and MUST
  // NOT carry these.
  expect(res.headers.get('Signature-Error')).toBeNull()
  expect(res.headers.get('Accept-Signature-Scheme')).toBeNull()
  expect(res.headers.get('Accept-Signature-Alg')).toBeNull()
  // Nor a challenge: there is nothing the agent can go and get.
  expect(res.headers.get('AAuth-Requirement')).toBeNull()
  const body = (await res.json()) as Record<string, unknown>
  expect(body.error).toBe(error)
  return body
}

/**
 * Dispatch a signed request with extra bindings. `SELF.fetch` runs against the
 * worker's own configured env, so the two env-driven refusals — a superseding
 * event and a dead status channel — call the app directly instead.
 */
async function withEnv(token: string, overrides: Record<string, string>): Promise<Response> {
  const url = `${RESOURCE}/agent/echo`
  const { headers } = await httpsigFetch(url, {
    dryRun: true,
    method: 'GET',
    signingKey: agentKey.privateJwk,
    signatureKey: { type: 'jwt', jwt: token },
    components: ['@method', '@authority', '@path', 'signature-key'],
  })
  const ctx = createExecutionContext()
  const res = await app.fetch(new Request(url, { method: 'GET', headers }), { ...env, ...overrides }, ctx)
  await waitOnExecutionContext(ctx)
  return res
}

describe('the four interop cases', () => {
  it('1. valid — a fresh Senior token is accepted', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const res = await signedGet(agentKey, token)

    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.verified).toBe(true)
    expect(body.atf.level).toBe('senior')
    expect(body.atf.profile).toBe('csa-atf:0.9.1')
    expect(body.agent_token.iss).toBe(AP)
    // The grade is the provider's assertion, and the body says so.
    expect(body.binding_status).toBe('ap-asserted')
    expect(body.limits.join(' ')).toContain('did not verify the ATF evaluator')
  })

  it('2. expired — a token past exp is refused as expired_jwt', async () => {
    const t = now()
    const token = await mintAgentToken(apKey, agentKey, {
      payload: { iat: t - 7200, exp: t - 3600 },
    })
    const res = await signedGet(agentKey, token)

    expect(res.status).toBe(401)
    expect(res.headers.get('Signature-Error')).toBe('error=expired_jwt')
  })

  it('3. tampered — level raised to principal is refused on the signature', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const forged = tamper(token, (p) => {
      p[ATF_CLAIM].level = 'principal'
    })
    const res = await signedGet(agentKey, forged)

    expect(res.status).toBe(401)
    // The signature is checked over the raw segments before anything is
    // parsed out of them, so this is an invalid signature and never a
    // parse error or an accepted "principal".
    expect(res.headers.get('Signature-Error')).toBe('error=invalid_jwt')
  })

  it('4. no-atf — a valid agent token with no grade gets the challenge', async () => {
    const token = await mintAgentToken(apKey, agentKey, { atf: null })
    const res = await signedGet(agentKey, token)

    const body = await expectChallenge(res)
    expect(body.error).toBe('agent_token_required')
    expect(String(body.detail)).toContain(ATF_CLAIM)
  })
})

describe('refusals no fresh token repairs (403)', () => {
  it('atf_subject_mismatch — the provider contradicted itself', async () => {
    const token = await mintAgentToken(apKey, agentKey, {
      atf: atfClaim({ workload_id: 'spiffe://example.org/agent/somebody-else' }),
    })
    const res = await signedGet(agentKey, token)

    const body = await expectDeny(res, 'atf_subject_mismatch')
    expect(String(body.detail)).toContain('somebody-else')
  })

  it('atf_appraisal_superseded — a demotion outranks an unexpired token', async () => {
    const token = await mintAgentToken(apKey, agentKey, { atf: atfClaim({ sequence: 42 }) })
    // A superseding event at sequence 43 for this subject.
    const res = await withEnv(token, {
      ATF_SUPERSEDED: JSON.stringify([{ appraisal_subject: SUBJECT, sequence: 43 }]),
    })

    const body = await expectDeny(res, 'atf_appraisal_superseded')
    expect(String(body.detail)).toContain('42')
  })

  it('atf_status_unavailable — unknown is not current, so it fails closed', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const res = await withEnv(token, { ATF_STATUS: 'unreachable' })
    await expectDeny(res, 'atf_status_unavailable')
  })
})

describe('conditions a better token fixes (401 challenge)', () => {
  it('no credentials at all', async () => {
    const res = await SELF.fetch(`${RESOURCE}/agent/echo`)
    await expectChallenge(res)
    // And what shape to sign in on the retry.
    expect(res.headers.get('Accept-Signature-Scheme')).toBe('jwt')
    expect(res.headers.get('Accept-Signature')).toContain('@authority')
  })

  it('an untrusted agent provider', async () => {
    const token = await mintAgentToken(otherApKey, agentKey, { iss: OTHER_AP })
    const res = await signedGet(agentKey, token)
    const body = await expectChallenge(res)
    expect(String(body.detail)).toContain(OTHER_AP)
  })

  it('a level below the minimum', async () => {
    const token = await mintAgentToken(apKey, agentKey, { atf: atfClaim({ level: 'junior' }) })
    const res = await signedGet(agentKey, token)
    const body = await expectChallenge(res)
    expect(String(body.detail)).toContain('junior')
  })

  it('an unknown level is not ranked and never clears', async () => {
    const token = await mintAgentToken(apKey, agentKey, { atf: atfClaim({ level: 'archmage' }) })
    const res = await signedGet(agentKey, token)
    const body = await expectChallenge(res)
    expect(String(body.detail)).toContain('archmage')
  })

  it('a profile this resource does not read', async () => {
    const token = await mintAgentToken(apKey, agentKey, {
      atf: atfClaim({ profile: 'csa-atf:0.8.0' }),
    })
    const res = await signedGet(agentKey, token)
    const body = await expectChallenge(res)
    expect(String(body.detail)).toContain('0.8.0')
  })

  it('an evaluator this resource has not named', async () => {
    const token = await mintAgentToken(apKey, agentKey, {
      atf: atfClaim({ appraisal_issuer: 'https://evaluator.invalid' }),
    })
    const res = await signedGet(agentKey, token)
    const body = await expectChallenge(res)
    expect(String(body.detail)).toContain('evaluator.invalid')
  })

  it('an appraisal that has lapsed, even inside a live token', async () => {
    // The token is good for an hour; the grade behind it is not. A token must
    // not outlive the evidence behind it. This is the case the ATF expiry
    // check exists for — the token layer sees nothing wrong.
    const token = await mintAgentToken(apKey, agentKey, {
      atf: atfClaim({ exp: now() - 3600 }),
    })
    const res = await signedGet(agentKey, token)
    const body = await expectChallenge(res)
    expect(String(body.detail)).toContain('expired')
  })

  it('applies the same clock tolerance to the appraisal as to the token', async () => {
    // With zero tolerance here and 60 seconds at the token layer, a token in
    // that window would be refused as a stale appraisal rather than as
    // expired_jwt — the same condition reporting under two codes depending on
    // how fast the caller was. Just inside the tolerance is accepted.
    const token = await mintAgentToken(apKey, agentKey, {
      atf: atfClaim({ exp: now() - 5 }),
    })
    const res = await signedGet(agentKey, token)
    expect(res.status).toBe(200)
  })
})

describe('check order', () => {
  it('reports the subject mismatch, not the low level, when both are wrong', async () => {
    // A claim that contradicts the token carrying it is incoherent, and
    // policy applied to an incoherent claim means nothing. The actionable
    // answer is the binding, not "go get a better grade" — which would return
    // the same contradiction.
    const token = await mintAgentToken(apKey, agentKey, {
      atf: atfClaim({ level: 'junior', workload_id: 'spiffe://example.org/agent/other' }),
    })
    const res = await signedGet(agentKey, token)
    await expectDeny(res, 'atf_subject_mismatch')
  })
})

describe('GET /api/summarize', () => {
  it('runs the same gate, then asks who the person is', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const res = await signedGet(agentKey, token, '/api/summarize')

    expect(res.status).toBe(401)
    expect(res.headers.get('AAuth-Requirement')).toBe('requirement=person-token')
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('person_token_required')
    expect(String(body.detail)).toContain('not permission')
  })

  it('refuses a short grade before it ever gets to the person', async () => {
    const token = await mintAgentToken(apKey, agentKey, { atf: atfClaim({ level: 'junior' }) })
    const res = await signedGet(agentKey, token, '/api/summarize')
    await expectChallenge(res)
  })
})
