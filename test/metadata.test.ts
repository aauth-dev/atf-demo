// The public surface: metadata, health, and the challenge carrier.

import { describe, expect, it } from 'vitest'
import { SELF, createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test'
import { parseRequirementHeader } from '@aauth/protocol'
import app from '../src/app'
import { ATF_POLICY } from '../src/config'
import { RESOURCE } from './helpers'

describe('metadata', () => {
  it('publishes the ATF policy under the namespace ATF owns', async () => {
    const res = await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)
    expect(res.status).toBe(200)
    const metadata = (await res.json()) as Record<string, any>

    expect(metadata.issuer).toBe(RESOURCE)
    expect(metadata.access_mode).toBe('agent-token')

    const policy = metadata[ATF_POLICY]
    expect(policy).toBeDefined()
    expect(policy.profiles).toEqual(['csa-atf:0.9.1'])
    expect(policy.minimum_level).toBe('senior')
    expect(policy.evaluators).toEqual(['https://demo.verifiedagents.ai'])

    // No status_channel and no on_status_unreachable. The channel is the
    // evaluator's, and the evaluator names it inside the signed appraisal as
    // status.channel / status.on_unreachable. Republishing it here asserted
    // by hand, unsigned, something the evaluator asserts under signature —
    // and the copy was wrong: it named a host that does not resolve, beside a
    // fail-closed promise the code did not keep. Withdrawal is now AAuth
    // revocation, advertised as revocation_endpoint.
    expect(policy.status_channel).toBeUndefined()
    expect(policy.on_status_unreachable).toBeUndefined()
  })

  it('advertises a revocation endpoint, as a resource taking agent tokens SHOULD', async () => {
    const res = await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)
    const metadata = (await res.json()) as Record<string, unknown>
    // AAuth §Token Revocation: under identity-based access the agent presents
    // its agent token straight to the resource, so the provider has no record
    // of which resources hold it and needs somewhere to call.
    expect(metadata.revocation_endpoint).toBe(`${RESOURCE}/revoke`)
  })

  it('publishes no jwks_uri: it issues no tokens and signs no calls', async () => {
    const res = await SELF.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)
    const metadata = (await res.json()) as Record<string, unknown>
    expect(metadata.jwks_uri).toBeUndefined()

    // And there is no key to serve.
    expect((await SELF.fetch(`${RESOURCE}/.well-known/jwks.json`)).status).toBe(404)
  })

  it('answers /health', async () => {
    const res = await SELF.fetch(`${RESOURCE}/health`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ status: 'ok' })
  })

  it('exposes the AAuth headers to cross-origin readers', async () => {
    const res = await SELF.fetch(`${RESOURCE}/agent/echo`, {
      headers: { Origin: 'https://playground.aauth.dev' },
    })
    const exposed = res.headers.get('Access-Control-Expose-Headers') ?? ''
    expect(exposed).toContain('AAuth-Requirement')
    expect(exposed).toContain('Signature-Error')
  })
})

describe('the challenge carrier', () => {
  async function challenge(overrides: Record<string, string>): Promise<string> {
    const ctx = createExecutionContext()
    const res = await app.fetch(
      new Request(`${RESOURCE}/agent/echo`),
      { ...env, ...overrides },
      ctx
    )
    await waitOnExecutionContext(ctx)
    return res.headers.get('AAuth-Requirement')!
  }

  it('bare is the default, and is AAuth as written', async () => {
    expect(await challenge({})).toBe('requirement=agent-token')
  })

  it('params serializes as a well-formed RFC 8941 Dictionary', async () => {
    // Not shipped — see the note on buildAtfChallenge and AAuth issue #145.
    // What is asserted here is only that the alternative is correctly encoded,
    // so switching carriers is a config change and not a debugging session.
    const value = await challenge({ ATF_CHALLENGE_CARRIER: 'params' })
    expect(value).toBe(
      'requirement=agent-token;atf-profile="csa-atf:0.9.1";atf-level="senior"'
    )

    // An existing AAuth parser reads it as the same requirement and ignores
    // the parameters it does not know, which is what makes the switch safe.
    expect(parseRequirementHeader(value).requirement).toBe('agent-token')
  })
})
