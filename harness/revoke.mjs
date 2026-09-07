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
// The revoking call is signed with the agent token itself. That is not a
// convenience: AAuth requires the recipient to accept revocation only from
// the issuer of the token being revoked, and the token's `iss` is what
// identifies the caller under the `jwt` scheme. A provider revoking in
// earnest would sign as itself with `jwks_uri`; either way the identity has
// to equal the `iss` in the body.

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

console.log(`iss  ${iss}`)
console.log(`jti  ${jti}`)
console.log(`exp  ${exp}`)

const before = await call('GET /agent/echo — before revocation')

// `exp` is not in AAuth's revocation request as written. It is proposed in
// https://github.com/dickhardt/AAuth/issues/146, because without it the
// recipient has no way to size its store: the entry only has to outlive the
// token, and nothing in the request says when that is. Sent here so the
// resource can use it; omit it and the resource falls back to 24 hours.
const body = JSON.stringify({ iss, jti, exp })

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
