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
//   ap.atf-demo.local     does not resolve in DNS. Nothing can fetch its
//                         keys, which is exactly why the local resource needs
//                         AGENT_PROVIDER_JWKS. Fast, offline, no deploy.
//
//   ap.atf-demo.aauth.dev resolves. The deployed resource fetches its
//                         discovery document and JWKS over the public
//                         internet and selects the key by `kid`, so the real
//                         discovery path is exercised rather than overridden.
//
// Pick with AP_ISSUER, or `--public`. The provider key persists under
// harness/ap/<host>/private/, so the published JWKS stays valid across runs.
const PUBLIC_AP = 'https://ap.atf-demo.aauth.dev'
export const AP_ISSUER =
  process.env.AP_ISSUER ??
  (process.argv.includes('--public') ? PUBLIC_AP : 'https://ap.atf-demo.local')
export const RESOURCE =
  process.env.RESOURCE_URL ??
  (AP_ISSUER === PUBLIC_AP ? 'https://atf-demo.aauth.dev' : 'http://localhost:8787')

// provider.mjs reads SUMMIT_PROVIDER_HOME to decide where to put private/,
// public/ and out/. Set it before importing so nothing lands in the summit
// repository.
const AP_HOME = path.join(AP_HOME_ROOT, new URL(AP_ISSUER).hostname)
process.env.SUMMIT_PROVIDER_HOME = AP_HOME

const { initialize, issue } = await import('./provider.mjs')

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
  // AP_HOME is deliberately not wiped. provider.mjs persists its signing key
  // there, and rotating it would invalidate the JWKS already published at
  // ap/jwks.json — every previously issued token with it.

  // 1. The agent provider: generate its key, write its discovery documents.
  initialize(AP_ISSUER)
  const jwks = JSON.parse(
    fs.readFileSync(path.join(AP_HOME, 'public', '.well-known', 'jwks.json'), 'utf8')
  )
  console.log(`agent provider ${AP_ISSUER}, kid ${jwks.keys[0].kid}`)

  const now = Math.floor(Date.now() / 1000)
  const cases = {}

  // 2. valid — a fresh Senior token.
  {
    const result = issue({ issuer: AP_ISSUER, appraisal: currentAppraisal(now, 3600), now })
    cases.valid = {
      token: result.token,
      key: agentJwk(result.agentPrivate),
      note: 'fresh Senior appraisal, one hour',
    }
  }

  // 3. expired — a token with a lifetime measured in seconds. The runner
  //    waits it out rather than backdating, so the expiry is real.
  {
    const result = issue({
      issuer: AP_ISSUER,
      appraisal: currentAppraisal(now, TTL_SHORT),
      now,
      ttl: TTL_SHORT,
    })
    cases.expired = {
      token: result.token,
      key: agentJwk(result.agentPrivate),
      expiresAt: result.payload.exp,
      note: `expires at ${new Date(result.payload.exp * 1000).toISOString()}`,
    }
  }

  // 4. tampered — the valid token with `level` raised from senior to
  //    principal in the payload segment, signature left alone. This is the
  //    edit Imran's own transcript makes.
  {
    const result = issue({ issuer: AP_ISSUER, appraisal: currentAppraisal(now, 3600), now })
    const [h, p, s] = result.token.split('.')
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString())
    payload['https://agentictrustframework.ai/atf'].level = 'principal'
    const tampered = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.')
    cases.tampered = {
      token: tampered,
      key: agentJwk(result.agentPrivate),
      note: 'payload edited: atf.level senior → principal',
    }
  }

  // 5. no-atf — a well-formed agent token from the same trusted provider that
  //    carries no grade. Needs no appraisal, and so no second signature from
  //    the evaluator: the case runs on a holiday.
  {
    const result = issue({ issuer: AP_ISSUER, noAtf: true, now })
    cases['no-atf'] = {
      token: result.token,
      key: agentJwk(result.agentPrivate),
      note: 'valid agent token, no ATF claim',
    }
  }

  writeJson(path.join(OUT, 'cases.json'), cases)

  // 6. The public half of the provider, for the worker to serve at
  //    ap.atf-demo.aauth.dev. Only ever the JWKS and the discovery document —
  //    the signing key stays under harness/ap/, which is gitignored. This is
  //    committed so a deploy can serve it without the harness having run.
  if (AP_ISSUER.startsWith('https://ap.atf-demo.aauth.dev')) {
    writeJson(path.join(HERE, '..', 'ap', 'jwks.json'), jwks)
    console.log('wrote ap/jwks.json (public key only) — commit and deploy to publish it')
  }

  // 7. The dev override the resource needs to verify tokens from an issuer
  //    that does not resolve. Written as .dev.vars, which wrangler dev reads
  //    and which is gitignored.
  const devVars = [
    `RESOURCE_URL=${RESOURCE}`,
    `AGENT_PROVIDERS=${AP_ISSUER}`,
    `AGENT_PROVIDER_JWKS=${JSON.stringify({ [AP_ISSUER]: jwks })}`,
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
