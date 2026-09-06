// Stand up a local agent provider and mint the four test tokens.
//
// Nothing here talks to the network and nothing here needs Imran or Josh. The
// provider is the summit's own `provider.mjs` (see the note at the top of the
// harness copy), running with its own freshly generated key under
// harness/ap/private/. The appraisal is the committed evaluator output from
// the summit repo with its validity window moved onto the current clock.
//
// ── The appraisal signature will not verify, and that is the design ────────
//
// `appraisal-source.json` is Josh's real signed output; its window closed at
// 2026-09-05T18:56:57Z. Bumping `iat`/`exp` to make it usable today
// invalidates the evaluator's Ed25519 signature over it, because the
// signature covers those fields.
//
// That breaks nothing, because this resource never verifies that signature.
// The ATF claim carries `appraisal_hash` — a digest of the complete signed
// appraisal — but no URI to resolve the document behind it, so the grade
// reaches the resource as the agent provider's assertion and is held on the
// agent provider's authority. Verifying the AP's signature is the whole of
// what the resource checks. A future reader finding a bad evaluator signature
// here should not file it as a bug: it is the direct consequence of the
// carriage decision, and it is what "the AP asserts the grade" means.
//
// The provider itself only checks that a signature *member is present*, that
// the profile is csa-atf 0.9.1, that the decision is qualifying, and that the
// appraisal has not expired. It does not verify the signature either — its
// own transcript says so, and calls that the relying party's job.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const AP_HOME_ROOT = path.join(HERE, 'ap')
const OUT = path.join(HERE, 'out')

// The local agent provider's issuer. provider.mjs requires an HTTPS origin
// with no path; this one does not resolve in DNS, which is exactly why the
// resource needs AGENT_PROVIDER_JWKS to verify tokens from it.
// Two providers, because two things need proving.
//
//   ap.atf-demo.local        does not resolve in DNS. Nothing can fetch its
//                            keys, which is exactly why the local resource
//                            needs AGENT_PROVIDER_JWKS. Offline, no deploy,
//                            no hardware. The default.
//
//   dickhardt.github.io      resolves, and has since June. Its discovery
//                            document and JWKS are already published, and
//                            name a key whose private half is in this
//                            machine's Secure Enclave. The deployed resource
//                            fetches those over the public internet and
//                            verifies against them, so the real discovery
//                            path runs with nothing stood up to serve it.
//                            Requires that machine. `--enclave`.
//
// Pick with `--enclave`, or AP_ISSUER for anything else.
const ENCLAVE_AP = 'https://dickhardt.github.io'
const useEnclave = process.argv.includes('--enclave')
export const AP_ISSUER =
  process.env.AP_ISSUER ?? (useEnclave ? ENCLAVE_AP : 'https://ap.atf-demo.local')
export const RESOURCE =
  process.env.RESOURCE_URL ??
  (useEnclave ? 'https://atf-demo.aauth.dev' : 'http://localhost:8787')

// provider.mjs reads SUMMIT_PROVIDER_HOME to decide where to put private/,
// public/ and out/. Set it before importing so nothing lands in the summit
// repository.
const AP_HOME = path.join(AP_HOME_ROOT, new URL(AP_ISSUER).hostname)
process.env.SUMMIT_PROVIDER_HOME = AP_HOME

const { initialize, issue } = await import('./provider.mjs')
const { mint: mintEnclave, ENCLAVE_SUB } = useEnclave
  ? await import('./enclave.mjs')
  : { mint: null, ENCLAVE_SUB: null }

/**
 * One token, from whichever provider is selected.
 *
 * The local path generates a provider key and signs with it. The enclave path
 * keeps `issue()`'s payload — the ATF claim and the appraisal-bounded expiry
 * are the same either way — and replaces the signature with one made by the
 * key dickhardt.github.io already publishes. Same claim shape, different
 * signer, so every case below is written once.
 */
async function mintToken({ appraisal, now, ttl, noAtf = false }) {
  if (useEnclave) {
    const r = await mintEnclave({ appraisal, now, ttl, noAtf })
    return { token: r.token, payload: r.payload, key: r.agentJwk }
  }
  const r = issue({ issuer: AP_ISSUER, appraisal, now, ttl, noAtf })
  return { token: r.token, payload: r.payload, key: agentJwk(r.agentPrivate) }
}

const TTL_SHORT = 60 // the `expired` case waits this out, so keep it short

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`)
}

// `issue()` returns the agent's private key as a KeyObject and writes the
// PKCS#8 PEM only from its CLI path. Imran will be reading that PEM off disk,
// so this is the same conversion he needs: PEM (or KeyObject) → JWK, with the
// fully-specified alg RFC 9864 and AAuth require.
function agentJwk(privateKeyOrPem) {
  const key =
    typeof privateKeyOrPem === 'string' || Buffer.isBuffer(privateKeyOrPem)
      ? crypto.createPrivateKey(privateKeyOrPem)
      : privateKeyOrPem
  return { ...key.export({ format: 'jwk' }), alg: 'Ed25519' }
}

/** The committed appraisal, moved onto the current clock. */
function currentAppraisal(now, lifetime) {
  const source = JSON.parse(fs.readFileSync(path.join(HERE, 'appraisal-source.json'), 'utf8'))
  return { ...source, iat: now, exp: now + lifetime }
}

async function main() {
  fs.rmSync(OUT, { recursive: true, force: true })

  // 1. The agent provider.
  //
  // Enclave mode has nothing to set up: the key and its published JWKS have
  // existed since June, and `resolveKey` fetches that JWKS and matches it to
  // the local Secure Enclave key. If this machine does not hold it, that
  // throws — the honest failure, rather than quietly signing with some other
  // key the resource would then refuse.
  //
  // Local mode generates a provider key and writes its discovery documents
  // under harness/ap/, which is gitignored. Nothing serves them; the resource
  // reads them through AGENT_PROVIDER_JWKS.
  let jwks
  if (useEnclave) {
    const { resolved } = await (await import('./enclave.mjs')).resolveEnclaveKey()
    jwks = { keys: [resolved.publicJwk] }
    console.log(
      `agent provider ${AP_ISSUER}, kid ${resolved.kid}, ` +
        `${resolved.algorithm} in the ${resolved.backend}, already published`
    )
  } else {
    initialize(AP_ISSUER)
    jwks = JSON.parse(
      fs.readFileSync(path.join(AP_HOME, 'public', '.well-known', 'jwks.json'), 'utf8')
    )
    console.log(`agent provider ${AP_ISSUER}, kid ${jwks.keys[0].kid}`)
  }

  const now = Math.floor(Date.now() / 1000)
  const cases = {}

  // 2. valid — a fresh Senior token.
  {
    const result = await mintToken({ appraisal: currentAppraisal(now, 3600), now })
    cases.valid = {
      token: result.token,
      key: result.key,
      note: 'fresh Senior appraisal, one hour',
    }
  }

  // 3. expired — a token with a lifetime measured in seconds. The runner
  //    waits it out rather than backdating, so the expiry is real.
  {
    const result = await mintToken({
      appraisal: currentAppraisal(now, TTL_SHORT),
      now,
      ttl: TTL_SHORT,
    })
    cases.expired = {
      token: result.token,
      key: result.key,
      expiresAt: result.payload.exp,
      note: `expires at ${new Date(result.payload.exp * 1000).toISOString()}`,
    }
  }

  // 4. tampered — the valid token with `level` raised from senior to
  //    principal in the payload segment, signature left alone. This is the
  //    edit Imran's own transcript makes.
  {
    const result = await mintToken({ appraisal: currentAppraisal(now, 3600), now })
    const [h, p, sig] = result.token.split('.')
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString())
    payload['https://agentictrustframework.ai/atf'].level = 'principal'
    const tampered = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), sig].join('.')
    cases.tampered = {
      token: tampered,
      key: result.key,
      note: 'payload edited: atf.level senior → principal',
    }
  }

  // 5. no-atf — a well-formed agent token from the same trusted provider that
  //    carries no grade. Needs no appraisal, and so no second signature from
  //    the evaluator: the case runs on a holiday.
  {
    const result = await mintToken({ noAtf: true, now })
    cases['no-atf'] = {
      token: result.token,
      key: result.key,
      note: 'valid agent token, no ATF claim',
    }
  }

  writeJson(path.join(OUT, 'cases.json'), cases)

  // 6. The dev override the resource needs to verify tokens from an issuer
  //    that does not resolve. Written as .dev.vars, which wrangler dev reads
  //    and which is gitignored.
  const devVars = [
    `RESOURCE_URL=${RESOURCE}`,
    `AGENT_PROVIDERS=${AP_ISSUER}`,
    // Only the unresolvable issuer needs the override. dickhardt.github.io
    // publishes its JWKS, so overriding it would skip the discovery this mode
    // exists to exercise.
    ...(useEnclave ? [] : [`AGENT_PROVIDER_JWKS=${JSON.stringify({ [AP_ISSUER]: jwks })}`]),
    'ATF_CHALLENGE_CARRIER=bare',
    '',
  ].join('\n')
  fs.writeFileSync(path.join(HERE, '..', '.dev.vars'), devVars)

  console.log(`wrote ${path.relative(process.cwd(), path.join(OUT, 'cases.json'))}`)
  console.log(`wrote .dev.vars (RESOURCE_URL=${RESOURCE}, AP JWKS override)`)
  for (const [name, c] of Object.entries(cases)) {
    console.log(`  ${name.padEnd(10)} ${c.note}`)
  }
}

await main()
