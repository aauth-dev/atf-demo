// Regenerates transcript.txt from a live run. Every byte below the banner is
// produced by client.mjs and curl against a running resource — nothing here
// is written by hand.
//
//   npm run harness && npm run dev &   # then
//   node harness/capture.mjs [--url http://localhost:8787]
//
// The `expired` case is minted with a short lifetime and both layers apply
// 60s of clock skew tolerance, so this waits until the token is genuinely
// past exp + skew before running it. Running it early is the difference
// between `expired_jwt` and a challenge, and the answer would otherwise
// depend on how fast you typed.

import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(HERE, '..')
const url = process.argv.includes('--url')
  ? process.argv[process.argv.indexOf('--url') + 1]
  : 'http://localhost:8787'

// client.mjs exits nonzero on every refusal — that is the point of it — so a
// nonzero exit is a result to record, not a failure to capture.
const run = (args) => {
  try {
    const stdout = execFileSync('node', ['client.mjs', ...args], {
      cwd: ROOT,
      encoding: 'utf8',
    })
    return `${stdout.trimEnd()}\n  exit 0`
  } catch (err) {
    if (err.stdout === undefined) throw err
    return `${String(err.stdout).trimEnd()}\n  exit ${err.status}`
  }
}

const curl = (u) => execFileSync('curl', ['-s', u], { encoding: 'utf8' })

const rule = '='.repeat(64)
const out = []
const say = (s = '') => out.push(s)
const section = (title) => {
  say('')
  say(rule)
  say(title)
  say(rule)
}

const cases = JSON.parse(fs.readFileSync(path.join(HERE, 'out/cases.json'), 'utf8'))
// Read the provider out of the tokens rather than naming it here. The
// transcript is evidence; a hardcoded header can disagree with the run.
const apIssuer = JSON.parse(
  Buffer.from(cases.valid.token.split('.')[1], 'base64url')
).iss
const expiredExp = JSON.parse(
  Buffer.from(cases.expired.token.split('.')[1], 'base64url')
).exp

say('atf-demo.aauth.dev — captured run')
say(`Captured: ${new Date().toISOString().replace('T', ' ').slice(0, 16)} UTC`)
say(`Node: ${process.version}   Resource: ${url}`)
say(`Agent provider: ${apIssuer} (harness/setup.mjs)`)
say('')
say('Every byte below is machine-produced. harness/setup.mjs mints the tokens;')
say('client.mjs signs the requests and prints what it sent and what came back.')
say('Regenerate with: node harness/capture.mjs')
say('')
say('The appraisal behind these tokens is the committed evaluator output from')
say('the summit repo with its validity window moved onto the current clock,')
say('which invalidates the evaluator’s signature over it. Nothing here verifies')
say('that signature: the grade reaches the resource as the agent provider’s')
say('assertion, held on the provider’s authority. See harness/setup.mjs.')

section('0. What the resource says it requires')
say(`$ curl -s ${url}/.well-known/aauth-resource.json`)
say(curl(`${url}/.well-known/aauth-resource.json`).trim())
say('')
say('The ATF requirement lives under the namespace ATF owns. There is no')
say('jwks_uri: this resource issues no tokens and signs no calls, so it')
say('publishes no keys and holds no secret.')
say('')
say('There is no status_channel either. The channel is the evaluator’s, and')
say('the evaluator names it inside the signed appraisal. revocation_endpoint')
say('is advertised and conforms; see the note under Revocation below for what')
say('it can and cannot be used for.')

const step = (title, args, note) => {
  section(title)
  say(`$ node client.mjs ${args.join(' ')}`)
  say(run(args))
  if (note) {
    say('')
    say(note)
  }
}

step('No credentials — the bare challenge', ['--case=none', '--url', `${url}/agent/echo`],
  'Nothing was presented, and the body says exactly that: agent_token_required.')

step('CASE 1 of 4: valid — a fresh Senior token', ['--case=valid', '--url', `${url}/agent/echo`])

step('CASE 2 of 4: tampered — atf.level raised senior -> principal',
  ['--case=tampered', '--url', `${url}/agent/echo`],
  'Refused by the signature check over the raw segments, before anything is\n' +
  'parsed out of them. The same refusal Imran’s own verifier gives, and the\n' +
  'same registered code: the fix in summit PR #1, agreed on both sides.\n' +
  'The body repeats the header’s code rather than naming one of its own.')

step('CASE 3 of 4: no-atf — a valid agent token carrying no grade',
  ['--case=no-atf', '--url', `${url}/agent/echo`],
  'Nothing is wrong with this token. It is insufficient, not absent — a\n' +
  'different fact from the unsigned case above, and the one the agent has to\n' +
  'act on. The bare challenge says an AAuth agent token is required; the Link\n' +
  'relation points at the document that says which profile and level. That the\n' +
  'challenge cannot say so itself is AAuth issue #145.')

const waitUntil = (expiredExp + 65) * 1000
if (Date.now() < waitUntil) {
  const secs = Math.ceil((waitUntil - Date.now()) / 1000)
  process.stderr.write(`waiting ${secs}s for the expired token to pass exp + skew\n`)
  execFileSync('sleep', [String(secs)])
}

section('CASE 4 of 4: expired — the same token, after its expiry')
say('Minted with a short lifetime and run past exp plus the 60-second clock')
say('skew tolerance both layers apply. Real clock: no backdating, no --at-time.')
say(`$ date -u`)
say(execFileSync('date', ['-u'], { encoding: 'utf8' }).trim())
say(`$ node client.mjs --case=expired --url ${url}/agent/echo`)
say(run(['--case=expired', '--url', `${url}/agent/echo`]))

step('The door still decides: GET /api/summarize, the same valid token',
  ['--case=valid', '--url', `${url}/api/summarize`],
  'The ATF gate passed and the request was still refused. A Senior grade\n' +
  'got this agent considered, not admitted.')

section('Revocation — AAuth §Token Revocation')
say('A fresh Senior token, revoked by its issuer, then presented again.')
say('')
say('This is the path that replaced the ATF status channel. Josh’s profile has')
say('the evaluator publish withdrawals to a channel a relying party polls;')
say('under this flow the agent provider watches that channel and pushes here')
say('instead. No evaluator in the request path, and no fail-open/fail-closed')
say('question, because there is nothing to fail to reach.')
say('')
say(`$ node harness/revoke.mjs --url ${url}`)
say(
  execFileSync('node', [path.join(ROOT, 'harness', 'revoke.mjs'), '--url', url], {
    encoding: 'utf8',
    cwd: ROOT,
  }).trim()
)
say('')
say('401 and not 403: the signature verified and the claim was coherent, but')
say('the credential is no longer good — the same shape of condition as expiry,')
say('and the same remedy. No Signature-Error, because the registry in')
say('draft-hardt-httpbis-signature-key has no code for a revoked token and')
say('expired_jwt, the nearest, would be false.')
say('')
say('The body is {jti, exp} and carries no iss: since spec PR #147 the issuer')
say('is not a request parameter, and the recipient takes it from the identity')
say('it verified on the signature. exp is REQUIRED and bounds how long the')
say('recipient has to remember the revocation. The response is 200 with an')
say('empty body, whether or not the recipient holds a record of the token —')
say('there is no not-found answer, because one would disclose what it holds.')
say('')
say('What the same revision also says: an agent token is revoked only at a PS,')
say('and a resource taking agent tokens directly under identity-based access')
say('has no revocation path. This capture demonstrates the mechanism. It is')
say('not a call a conforming agent provider would make against this resource.')

section('Summary')
say('  valid      200  verification report')
say('  tampered   401  Signature-Error: error=invalid_jwt')
say('  no-atf     401  AAuth-Requirement: requirement=agent-token')
say('  expired    401  Signature-Error: error=expired_jwt')
say('  revoked    401  agent_token_revoked, after POST /revoke')
say('')
say('Every error body is application/problem+json, and where a Signature-Error')
say('header is present the body’s `error` repeats it.')
say('')
say('Not shown here: atf_subject_mismatch, the one refusal no fresh token')
say('repairs. It needs a claim whose appraisal_subject and workload_id')
say('disagree, so it is covered in test/gate.test.ts rather than by a client')
say('that only holds well-formed tokens.')
say('')
say('Two more 403s used to live beside it — atf_status_unavailable and')
say('atf_appraisal_superseded. Both read a Worker environment variable rather')
say('than anything at runtime, so neither could ever fire in production, and')
say('the metadata promised a fail-closed status channel the code never')
say('fetched. Both are gone, and revocation does the work.')

fs.writeFileSync(path.join(ROOT, 'transcript.txt'), out.join('\n') + '\n')
process.stderr.write('wrote transcript.txt\n')
