// Test scaffolding. Nothing here mocks the protocol: the tokens are real
// Ed25519 JWTs, the requests carry real RFC 9421 signatures, and the agent
// provider's discovery documents are served through a mocked outbound fetch
// the same way `AGENT_PROVIDER_JWKS` serves them in local dev.

import { SELF } from 'cloudflare:test'
import { calculateThumbprint, fetch as httpsigFetch } from '@hellocoop/httpsig'

export const RESOURCE = 'https://atf-demo.aauth.dev'
export const AP = 'https://ap.test'
export const OTHER_AP = 'https://other-ap.test'
export const EVALUATOR = 'https://demo.verifiedagents.ai'
export const ATF_CLAIM = 'https://agentictrustframework.ai/atf'
export const SUBJECT = 'spiffe://example.org/agent/planner'

export interface TestKey {
  privateKey: CryptoKey
  privateJwk: JsonWebKey
  publicJwk: JsonWebKey & { kid: string }
}

const enc = new TextEncoder()

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function generateEd25519(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey
  privateJwk.alg = 'Ed25519'
  const { d: _d, key_ops: _ko, ext: _ext, ...pub } = privateJwk as Record<string, unknown>
  const publicJwk = { ...pub, key_ops: ['verify'], alg: 'Ed25519' } as JsonWebKey
  const kid = await calculateThumbprint(publicJwk)
  return { privateKey: pair.privateKey, privateJwk, publicJwk: { ...publicJwk, kid } }
}

export async function signJWT(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey
): Promise<string> {
  const h = b64url(enc.encode(JSON.stringify(header)))
  const p = b64url(enc.encode(JSON.stringify(payload)))
  const sig = await crypto.subtle.sign('Ed25519', key, enc.encode(`${h}.${p}`))
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`
}

export function now(): number {
  return Math.floor(Date.now() / 1000)
}

export function cnfJwk(key: TestKey): JsonWebKey {
  const { kid: _kid, key_ops: _ko, ...jwk } = key.publicJwk as Record<string, unknown>
  return jwk as JsonWebKey
}

/** The ATF claim the summit agent provider mints, with overrides. */
export function atfClaim(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const t = now()
  return {
    profile: 'csa-atf:0.9.1',
    level: 'senior',
    appraisal_id: 'urn:uuid:f398589fc587869a9541b61c9ba19908',
    appraisal_issuer: EVALUATOR,
    appraisal_hash: 'sha256:4fe9bd1fa1512e7f375309b519ee9bfd960bf4532f4602d82f94baeb9a8a04b3',
    evidence_hash: 'sha256:be134c879a16ac04dc7527889b6f4fb1b92994dc6274778a79e45a1aa59f4fd2',
    appraisal_subject: SUBJECT,
    workload_id: SUBJECT,
    sequence: 42,
    exp: t + 3600,
    binding_status: 'demo-proposal',
    ...overrides,
  }
}

/**
 * An agent token as the summit provider issues it. `atf: null` omits the
 * claim entirely — the `no-atf` case.
 */
export async function mintAgentToken(
  apKey: TestKey,
  agentKey: TestKey,
  options: {
    iss?: string
    atf?: Record<string, unknown> | null
    payload?: Record<string, unknown>
  } = {}
): Promise<string> {
  const t = now()
  const iss = options.iss ?? AP
  const atf = options.atf === undefined ? atfClaim() : options.atf
  const payload: Record<string, unknown> = {
    iss,
    dwk: 'aauth-agent.json',
    sub: `aauth:planner@${new URL(iss).hostname}`,
    jti: crypto.randomUUID(),
    cnf: { jwk: cnfJwk(agentKey) },
    iat: t,
    exp: t + 3600,
    ...(atf ? { [ATF_CLAIM]: atf } : {}),
    ...options.payload,
  }
  return signJWT(
    { alg: 'Ed25519', typ: 'aa-agent+jwt', kid: apKey.publicJwk.kid },
    payload,
    apKey.privateKey
  )
}

/** Raise `atf.level` in the payload segment, leaving the signature alone. */
export function tamper(token: string, mutate: (payload: any) => void): string {
  const [h, p, s] = token.split('.')
  const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')))
  mutate(payload)
  return [h, b64url(enc.encode(JSON.stringify(payload))), s].join('.')
}

/** Sign a GET as the agent and dispatch it to the worker under test. */
export async function signedGet(
  agentKey: TestKey,
  token: string,
  path = '/agent/echo'
): Promise<Response> {
  const url = `${RESOURCE}${path}`
  const { headers } = await httpsigFetch(url, {
    dryRun: true,
    method: 'GET',
    signingKey: agentKey.privateJwk,
    signatureKey: { type: 'jwt', jwt: token },
    components: ['@method', '@authority', '@path', 'signature-key'],
  })
  return SELF.fetch(url, { method: 'GET', headers })
}

// ── Outbound fetch mock ──
// Tests and the worker share one isolate, so replacing globalThis.fetch is
// how agent provider discovery is served. SELF.fetch is a binding, unaffected.

const mockRoutes = new Map<string, Map<string, () => Response>>()
let mockInstalled = false

export function installMockFetch(): void {
  if (mockInstalled) return
  mockInstalled = true
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const href =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(href)
    const handler = mockRoutes.get(url.origin)?.get(url.pathname)
    if (!handler) throw new Error(`unmocked outbound fetch: ${href}`)
    return handler()
  }) as typeof fetch
}

/** Serve an agent provider's `aauth-agent.json` and its JWKS. */
export function mockAgentProvider(origin: string, key: TestKey): void {
  const paths = mockRoutes.get(origin) ?? new Map<string, () => Response>()
  paths.set('/.well-known/aauth-agent.json', () =>
    Response.json({ issuer: origin, jwks_uri: `${origin}/jwks.json` })
  )
  paths.set('/jwks.json', () => Response.json({ keys: [key.publicJwk] }))
  mockRoutes.set(origin, paths)
}
