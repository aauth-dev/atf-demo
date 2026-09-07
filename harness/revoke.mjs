// Revoke an agent token at the resource, and show that the same token stops
// working — AAuth §Token Revocation, end to end against a live endpoint.
//
//   node harness/revoke.mjs --url https://atf-demo.aauth.dev
//
// What this demonstrates is the path that replaced the ATF status channel.
// Josh's profile has the evaluator publish withdrawals to a channel a relying
// party polls. Under this flow the agent provider watches that channel and
// pushes here instead, so no evaluator sits in the request path and there is
// no fail-open/fail-closed question — there is nothing to fail to reach.
//
// The revoking call is signed with the agent token itself, so the resource
// takes `https://dickhardt.github.io` as the caller's identity and keys the
// revocation under it. Since spec PR #147 the issuer is not a request
// parameter at all — "the recipient takes it from the identity it verified
// on the signature", and "a caller cannot name an issuer it cannot sign for,
// so revoking another issuer's token is not something a recipient refuses,
// it is unreachable". A provider revoking in earnest signs with `jwks_uri`
// against the key its own metadata publishes.
//
// Note what the same revision says about this particular demonstration: an
// agent token is revoked only at a PS, and a resource taking agent tokens
// directly under identity-based access has no revocation path. The endpoint
// below conforms; the credential it is being asked to revoke does not belong
// here. Reaching this resource legitimately means the four-party flow, where
// the AS checks the ATF claim and issues an auth token, and the AS revokes
// that auth token here when the PS cascades. See demo/resource-contract.md.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { fetch as sign } from '@hellocoop/httpsig'

const HERE = path.dirname(fileURLToPath(import.meta.url))

const args = {}
for (const argv = process.argv.slice(2), i = { n: 0 }; i.n < argv.length; i.n++) {
  const a = argv[i.n]
  if (!a.startsWith('--')) continue
  const [k, ...v] = a.slice(2).split('=')
  if (v.length) args[k] = v.join('=')
  else if (argv[i.n + 1] && !argv[i.n + 1].startsWith('--')) args[k] = argv[++i.n]
  else args[k] = true
}

const base = (args.url ?? 'http://localhost:8787').replace(/\/$/, '')
const cases = JSON.parse(
  fs.readFileSync(args.cases ?? path.join(HERE, 'out', 'cases.json'), 'utf8')
)
const { token, key } = cases.valid

const payload = JSON.parse(
  Buffer.from(token.split('.')[1], 'base64url').toString('utf8')
)
const { iss, jti, exp } = payload

const show = (label, value) => console.log(`${String(label).padEnd(18)}${value}`)
const dump = async (res) => {
  console.log(`${res.status} ${res.statusText}`)
  for (const name of ['aauth-requirement', 'signature-error', 'link']) {
    const v = res.headers.get(name)
    if (v) show(`${name}:`, v)
  }
  const body = await res.text()
  if (!body) {
    console.log('(empty body)')
    return
  }
  try {
    console.log(JSON.stringify(JSON.parse(body), null, 2))
  } catch {
    console.log(body)
  }
}

const call = async (label) => {
  const { response } = await sign(`${base}/agent/echo`, {
    method: 'GET',
    signingKey: key,
    signatureKey: { type: 'jwt', jwt: token },
    components: ['@method', '@authority', '@path', 'signature-key'],
    returnSent: true,
  })
  console.log(`\n=== ${label} ===`)
  await dump(response)
  return response.status
}

console.log(`iss  ${iss}   (taken by the resource from the signature, not the body)`)
console.log(`jti  ${jti}`)
console.log(`exp  ${exp}`)

const before = await call('GET /agent/echo — before revocation')

// `jti` and `exp`, both REQUIRED, and no `iss` — that came out of the body
// in spec PR #147, which settled issue #146. `exp` is the revoked token's own
// expiration and it bounds how long the recipient has to remember the
// revocation: past that the token is refused on expiry alone.
const body = JSON.stringify({ jti, exp })

const { response: revoked, sent } = await sign(`${base}/revoke`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body,
  signingKey: key,
  signatureKey: { type: 'jwt', jwt: token },
  components: [
    '@method',
    '@authority',
    '@path',
    'content-digest',
    'content-type',
    'signature-key',
  ],
  returnSent: true,
})

console.log('\n=== POST /revoke ===')
console.log('--- sent ---')
show(sent.method, sent.url)
for (const name of ['content-digest', 'signature-input', 'signature-key']) {
  const v = sent.headers.get(name)
  if (v) show(`${name}:`, v)
}
console.log(body)
console.log('--- received ---')
await dump(revoked)

const after = await call('GET /agent/echo — after revocation')

console.log('\n=== result ===')
show('before:', before)
show('after:', after)
// The token was good and is now refused, and refused as a 401 rather than a
// 403: the credential is no longer valid and the remedy is another agent
// token, exactly as it is for an expired one.
process.exit(before === 200 && after === 401 ? 0 : 1)
