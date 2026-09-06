// Mint the test tokens as https://dickhardt.github.io, signing with the
// Secure Enclave key already published in that host's JWKS.
//
// This is the whole reason no agent provider has to be deployed. The
// discovery document and JWKS at dickhardt.github.io are already live and
// already name a key whose private half is in this machine's Secure Enclave,
// so a token signed here verifies against a published JWKS the resource
// fetches over the public internet. Nothing is stood up and nothing is
// hosted: the AP is a static file that has been there since June.
//
//   https://dickhardt.github.io/.well-known/aauth-agent.json
//   https://dickhardt.github.io/.well-known/jwks.json   kid 2026-06-11_577, ES256
//
// `@aauth/local-keys` has no API for extra claims — `signAgentToken` builds a
// fixed claim set — so this reuses provider.mjs to build the payload,
// including the ATF claim, and then signs that payload over the same
// `resolveKey` → `signHash` path signAgentToken itself uses. The private key
// never leaves the enclave; the helper returns a signature over a hash.
//
// The root key is ES256 and the summit provider's is Ed25519. Both must
// verify, which is why the resource never narrows `supportedAlgorithms`.

import { createHash } from 'node:crypto'
import { generateKeyPair, exportJWK } from 'jose'
import { issue } from './provider.mjs'

export const ENCLAVE_ISSUER = 'https://dickhardt.github.io'
export const ENCLAVE_SUB = 'aauth:local@dickhardt.github.io'

const LOCAL_KEYS = '@aauth/local-keys'

/** Resolve the published key to its local backend. Throws if this machine does
 *  not hold it — which is the honest failure, not a fallback to a soft key. */
export async function resolveEnclaveKey() {
  const lk = await import(LOCAL_KEYS)
  const resolved = await lk.resolveKey(ENCLAVE_ISSUER)
  return { resolved, driver: lk.getBackend(resolved.backend) }
}

/** The ephemeral key the agent token confirms in `cnf.jwk`, and signs its HTTP
 *  requests with. Fully-specified `alg` per RFC 9864, which AAuth requires and
 *  `@hellocoop/httpsig` reads the signing algorithm from. */
async function ephemeralKey() {
  const { publicKey, privateKey } = await generateKeyPair('Ed25519', { extractable: true })
  const pub = { ...(await exportJWK(publicKey)), alg: 'Ed25519' }
  const priv = { ...(await exportJWK(privateKey)), alg: 'Ed25519' }
  return { pub, priv }
}

/**
 * Mint one agent token as dickhardt.github.io.
 *
 * `issue()` builds the payload — the ATF claim, `appraisal_hash`, the
 * expiry floor at the appraisal's — and signs it with a provider key we throw
 * away. Only the payload is kept; the header and signature are replaced with
 * the enclave's.
 */
export async function mint({ appraisal, now, ttl, noAtf = false }) {
  const { resolved, driver } = await resolveEnclaveKey()
  const built = issue({
    issuer: ENCLAVE_ISSUER,
    agentId: ENCLAVE_SUB,
    appraisal,
    now,
    ttl,
    noAtf,
  })

  const { pub, priv } = await ephemeralKey()
  const payload = { ...built.payload, cnf: { jwk: pub } }
  const header = { alg: resolved.algorithm, typ: 'aa-agent+jwt', kid: resolved.kid }

  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
  const signingInput = `${b64(header)}.${b64(payload)}`
  const { signature } = await driver.signHash(
    resolved.keyId,
    createHash('sha256').update(signingInput).digest()
  )

  return {
    token: `${signingInput}.${Buffer.from(signature).toString('base64url')}`,
    payload,
    agentJwk: priv,
  }
}
