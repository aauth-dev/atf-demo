// The ATF gate: the four interop cases, the one refusal no fresh token
// repairs, revocation, and the two endpoints' contracts.

import { beforeAll, describe, expect, it } from 'vitest'
import { SELF } from 'cloudflare:test'
import { fetch as httpsigFetch } from '@hellocoop/httpsig'
import { clearMetadataCache } from '@aauth/resource'
import { parseRequirementHeader } from '@aauth/protocol'
import {
  AP,
  ATF_CLAIM,
  OTHER_AP,
  RESOURCE,
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
  // AAuth §Error Response Format: every error body is RFC 9457 problem
  // details, on a 401 as much as on a 403.
  expect(res.headers.get('Content-Type')).toContain('application/problem+json')
  const body = (await res.json()) as Record<string, unknown>
  // Where a Signature-Error is present the body must repeat it, never name a
  // code of its own. A body that disagrees with the header is read as a
  // contradiction by anyone comparing the two.
  const sigError = res.headers.get('Signature-Error')
  if (sigError) expect(`error=${String(body.error)}`).toBe(sigError)
  return body
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
    // Two statements about the binding, attributed to who made each. The
    // provider's own binding_status travels verbatim rather than being
    // replaced by this resource's word for it.
    expect(body.binding.established_by_this_resource).toBe('ap-asserted')
    expect(body.binding.asserted_by_agent_provider).toBe('demo-proposal')
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
    // Not `agent_token_required`: a valid agent token was presented. It is
    // insufficient for what this resource asks, which is a different fact and
    // the one the agent has to act on. `agent_token_required` is reserved for
    // a request that presented nothing.
    expect(body.error).toBe('agent_token_insufficient')
    expect(String(body.detail)).toContain(ATF_CLAIM)
  })

  it('the two 401 bodies are distinguishable: absent vs insufficient', async () => {
    const absent = await SELF.fetch(`${RESOURCE}/agent/echo`)
    expect(absent.status).toBe(401)
    expect(absent.headers.get('Content-Type')).toContain('application/problem+json')
    expect(((await absent.json()) as any).error).toBe('agent_token_required')

    const token = await mintAgentToken(apKey, agentKey, { atf: null })
    const insufficient = await signedGet(agentKey, token)
    expect(((await insufficient.json()) as any).error).toBe('agent_token_insufficient')
  })

  it('the expired body repeats the Signature-Error code, not a name of its own', async () => {
    const t = now()
    const token = await mintAgentToken(apKey, agentKey, {
      payload: { iat: t - 7200, exp: t - 3600 },
    })
    const res = await signedGet(agentKey, token)

    expect(res.headers.get('Signature-Error')).toBe('error=expired_jwt')
    expect(((await res.json()) as any).error).toBe('expired_jwt')
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

  it('is the only 403 this resource has', async () => {
    // Two more used to live here: atf_status_unavailable and
    // atf_appraisal_superseded. Both read a Worker environment variable
    // rather than anything at runtime, so in production neither could ever
    // fire, and the metadata promised a fail-closed status channel the code
    // never fetched. Withdrawal is now AAuth revocation, which is a 401.
    const res = await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)
    const policy = ((await res.json()) as any)[
      'https://agentictrustframework.ai/policy'
    ]
    expect(policy.status_channel).toBeUndefined()
    expect(policy.on_status_unreachable).toBeUndefined()
  })
})

describe('revocation (AAuth §Token Revocation)', () => {
  /** Sign a POST /revoke as `signerIss`, using the jwt scheme. */
  async function revoke(
    signerKey: TestKey,
    signerToken: string,
    body: Record<string, unknown>
  ): Promise<Response> {
    const url = `${RESOURCE}/revoke`
    const payload = JSON.stringify(body)
    const { headers } = await httpsigFetch(url, {
      dryRun: true,
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: payload,
      signingKey: signerKey.privateJwk,
      signatureKey: { type: 'jwt', jwt: signerToken },
      components: [
        '@method',
        '@authority',
        '@path',
        'content-digest',
        'content-type',
        'signature-key',
      ],
    })
    return SELF.fetch(url, { method: 'POST', headers, body: payload })
  }

  it('the metadata advertises the endpoint', async () => {
    const res = await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)
    expect(((await res.json()) as any).revocation_endpoint).toBe(`${RESOURCE}/revoke`)
  })

  it('refuses an unsigned revocation', async () => {
    const res = await SELF.fetch(`${RESOURCE}/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ iss: AP, jti: 'anything' }),
    })
    // Unsigned revocation would let anyone disable any agent by guessing a
    // jti. AAuth: recipients MUST verify the caller via HTTP signatures.
    expect(res.status).toBe(401)
  })

  it('refuses a revocation signed by someone other than the token issuer', async () => {
    // OTHER_AP holds a perfectly good token, and tries to revoke one of AP's.
    const otherToken = await mintAgentToken(otherApKey, agentKey, { iss: OTHER_AP })
    const res = await revoke(agentKey, otherToken, { iss: AP, jti: 'victim' })

    expect(res.status).toBe(403)
    expect(((await res.json()) as any).error).toBe('not_token_issuer')
  })

  it('revokes a token, and the next request with it is refused', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const jti = JSON.parse(
      atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
    ).jti as string

    // It works first.
    expect((await signedGet(agentKey, token)).status).toBe(200)

    // The provider withdraws it, signing as itself with its own agent token.
    const revocation = await revoke(agentKey, token, { iss: AP, jti })
    expect(revocation.status).toBe(200)
    expect(((await revocation.json()) as any).stored).toBe(true)

    // 401, not 403: the credential is no longer good and the remedy is
    // another agent token, exactly as it is for an expired one.
    const after = await signedGet(agentKey, token)
    expect(after.status).toBe(401)
    const body = (await after.json()) as any
    expect(body.error).toBe('agent_token_revoked')
    // No Signature-Error: the registry has no code for a revoked token, and
    // expired_jwt — the nearest — would be false.
    expect(after.headers.get('Signature-Error')).toBeNull()
    expect(after.headers.get('AAuth-Requirement')).toBe('requirement=agent-token')
  })

  it('revocation is keyed by (iss, jti), so it does not cross issuers', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const jti = JSON.parse(
      atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
    ).jti as string

    // OTHER_AP revokes the same jti in its own namespace. A jti is unique
    // only within its issuer, so this must not touch AP's token.
    const otherToken = await mintAgentToken(otherApKey, agentKey, { iss: OTHER_AP })
    expect((await revoke(agentKey, otherToken, { iss: OTHER_AP, jti })).status).toBe(200)

    expect((await signedGet(agentKey, token)).status).toBe(200)
  })

  it('rejects a body missing iss or jti', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    const res = await revoke(agentKey, token, { iss: AP })
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).error).toBe('invalid_request')
  })

  it('stores nothing for a token that has already expired', async () => {
    const token = await mintAgentToken(apKey, agentKey)
    // exp two hours in the past: the token is already refused on expiry, so
    // an entry would be storing nothing useful. AAuth wants a 200 either way
    // — "if the token was revoked or was already invalid".
    const res = await revoke(agentKey, token, {
      iss: AP,
      jti: crypto.randomUUID(),
      exp: now() - 7200,
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.revoked).toBe(true)
    expect(body.stored).toBe(false)
  })

  it('sizes the entry from exp when given one, and falls back to 24 hours', async () => {
    const token = await mintAgentToken(apKey, agentKey)

    const withExp = (await (
      await revoke(agentKey, token, {
        iss: AP,
        jti: crypto.randomUUID(),
        exp: now() + 300,
      })
    ).json()) as any
    // 300s plus the 60s clock tolerance, less however long the test took.
    expect(withExp.expires_in).toBeGreaterThan(300)
    expect(withExp.expires_in).toBeLessThanOrEqual(360)

    const withoutExp = await revoke(agentKey, token, {
      iss: AP,
      jti: crypto.randomUUID(),
    })
    // AAuth's revocation request has no exp field (spec issue #146), so a
    // caller following the spec as written lands here.
    expect(((await withoutExp.json()) as any).expires_in).toBe(86_400)

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
