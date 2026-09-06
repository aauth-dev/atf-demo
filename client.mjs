// The test client. Signs a request per RFC 9421, presents an AAuth agent
// token via `Signature-Key: sig=jwt;jwt="…"`, and prints both what went on
// the wire and what came back.
//
// This is the whole of the agent side for agent identity access: no person
// server, no challenge loop, nothing to obtain. `@hellocoop/httpsig`'s fetch
// does the signing; `returnSent: true` hands back the exact request, which is
// what makes the transcript evidence rather than description.
//
//   node client.mjs --case=valid       --url http://localhost:8787/agent/echo
//   node client.mjs --case=tampered    --url http://localhost:8787/agent/echo
//   node client.mjs --case=none        --url http://localhost:8787/agent/echo
//
// `--case=none` sends an unsigned request, to see the bare challenge.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { fetch as sign } from '@hellocoop/httpsig'

const HERE = path.dirname(fileURLToPath(import.meta.url))

// Accepts both `--key=value` and `--key value`.
const args = {}
for (const argv = process.argv.slice(2), i = { n: 0 }; i.n < argv.length; i.n++) {
  const a = argv[i.n]
  if (!a.startsWith('--')) continue
  const [k, ...v] = a.slice(2).split('=')
  if (v.length) args[k] = v.join('=')
  else if (argv[i.n + 1] && !argv[i.n + 1].startsWith('--')) args[k] = argv[++i.n]
  else args[k] = true
}

const url = args.url ?? 'http://localhost:8787/agent/echo'
const which = args.case ?? 'valid'

function show(label, value) {
  console.log(`${label.padEnd(18)}${value}`)
}

const res =
  which === 'none'
    ? await (async () => {
        console.log('--- sent ---')
        show('GET', url)
        console.log('(unsigned — no Signature, Signature-Input or Signature-Key)')
        return fetch(url)
      })()
    : await (async () => {
        const casesPath = args.cases ?? path.join(HERE, 'harness', 'out', 'cases.json')
        const cases = JSON.parse(fs.readFileSync(casesPath, 'utf8'))
        const testCase = cases[which]
        if (!testCase) {
          console.error(
            `no case "${which}" in ${casesPath}; have: ${Object.keys(cases).join(', ')}, none`
          )
          process.exit(2)
        }

        const { response, sent } = await sign(url, {
          method: 'GET',
          signingKey: testCase.key,
          signatureKey: { type: 'jwt', jwt: testCase.token },
          components: ['@method', '@authority', '@path', 'signature-key'],
          returnSent: true,
        })

        console.log('--- sent ---')
        show(sent.method, sent.url)
        for (const name of ['signature-input', 'signature', 'signature-key']) {
          const v = sent.headers.get(name)
          if (v) show(`${name}:`, v)
        }
        return response
      })()

console.log('\n--- received ---')
console.log(`${res.status} ${res.statusText}`)
for (const [name, value] of [...res.headers].sort()) {
  // Skip the noise a dev server adds; the AAuth and signature headers are
  // the ones the transcript is about.
  if (['date', 'content-length', 'vary', 'access-control-allow-origin'].includes(name)) continue
  show(`${name}:`, value)
}

const body = await res.text()
console.log()
try {
  console.log(JSON.stringify(JSON.parse(body), null, 2))
} catch {
  console.log(body)
}

// Nonzero on refusal, so a runner can assert without parsing.
process.exit(res.ok ? 0 : 1)
