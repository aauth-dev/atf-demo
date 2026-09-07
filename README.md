# atf-demo.aauth.dev — an AAuth resource that reads an ATF grade

Part of [AAuth](https://aauth.dev). Runs at
[atf-demo.aauth.dev](https://atf-demo.aauth.dev/.well-known/aauth-resource.json).

The relying party of the CSA Verifiable Agent Summit chain:

> TRACE is the evidence. ATF is the judgment. AAuth is the delivery.
> The relying party still decides.

An agent presents an AAuth agent token, signed by its agent provider, carrying a
`https://agentictrustframework.ai/atf` claim — a grade assigned by an ATF evaluator over a
TRACE runtime record. This resource verifies the provider's signature, reads the grade the
provider vouches for, applies its own policy, and then asks who the person is.

## What it verifies, and what it does not

It verifies the **agent provider's** signature over the agent token, and reads the grade
from the claim inside it.

It does **not** verify the **ATF evaluator's** signature over the appraisal. The claim
carries `appraisal_hash`, a SHA-256 digest of the complete signed appraisal, but no way to
resolve the document behind it — so there is nothing to check the digest against. The grade
therefore reaches this resource as the agent provider's assertion, held on the provider's
authority, exactly as `sub` and `cnf` are. The 200 body reports `binding_status:
"ap-asserted"` and says so in words.

The digests travel anyway. They cost nothing, and anyone who obtains the appraisal or the
TRACE record out of band can bind it to the token that carried them.

## Endpoints

| URL | |
|-----|---|
| `/.well-known/aauth-resource.json` | Resource metadata, carrying the ATF policy |
| `/agent/echo` | Agent identity access; reports what was verified |
| `/api/summarize` | The same gate, then a person token challenge |
| `/health` | `{ "status": "ok" }` |

There is no `/.well-known/jwks.json` and no signing key. Per AAuth §Resource Metadata,
`jwks_uri` is REQUIRED only of a resource that issues resource tokens or makes signed calls
of its own. This one issues nothing and signs nothing, so it publishes no keys and holds no
secret.

`/api/summarize` is the point of the demo. The ATF gate passes and the request is still
refused with `requirement=person-token`. A Senior grade gets an agent considered, not
admitted.

## The policy it publishes

```json
{
  "issuer": "https://atf-demo.aauth.dev",
  "access_mode": "agent-token",
  "revocation_endpoint": "https://atf-demo.aauth.dev/revoke",
  "https://agentictrustframework.ai/policy": {
    "profiles": ["csa-atf:0.9.1"],
    "minimum_level": "senior",
    "evaluators": ["https://demo.verifiedagents.ai"]
  }
}
```

Under the namespace ATF owns, alongside AAuth's own members. AAuth's document carries it;
ATF defines what goes in it.

## The gate

Check order is load-bearing.

| # | Check | On failure |
|---|-------|-----------|
| 1 | RFC 9421 signature, then `Signature-Key` scheme is `jwt` | 401 + `Signature-Error` |
| 2 | `typ` is `aa-agent+jwt` | 401 challenge |
| 3 | Token layer: structure, `cnf` binding, provider signature, then expiry | 401 + `Signature-Error` |
| 4 | `iss` is a trusted agent provider | 401 challenge |
| 5 | The ATF claim is present | 401 challenge |
| 6 | `profile` is one this resource reads | 401 challenge |
| 7 | `appraisal_issuer` is an evaluator this resource named | 401 challenge |
| 8 | `appraisal_subject` and `workload_id` agree | **403** `atf_subject_mismatch` |
| 9 | The appraisal has not lapsed | 401 challenge |
| 10 | `level` meets `minimum_level` | 401 challenge |
| 11 | The token has not been revoked | 401 `agent_token_revoked` |

Checks 1–7 and 9–10 are conditions a better agent token repairs, so they all get the same
401 challenge. Check 8 is the claim's internal consistency: the provider signed one token
carrying both `appraisal_subject` and `workload_id`, and if they disagree the provider has
contradicted itself. It runs before the policy checks, because policy applied to an
incoherent claim means nothing, and it is a 403 because a fresh token from the same provider
would carry the same contradiction. Check 11 is currency, and it is last because it is the
only check that reads storage — everything above it is a pure function of the token, so a
token failing one of them never costs a KV lookup.

Inside check 3, expiry is judged only after the provider's signature verifies. Before that
the payload is bytes the presenter chose, and `expired_jwt` means the named issuer minted
this and its lifetime ran out — report it from an unauthenticated read and any forgery can
produce it by carrying a past `exp`, sending an agent off to refresh a token that was never
the problem. Fixed in `@hellocoop/httpsig` 2.4.0 and `@aauth/resource` 2.2.0.

Two checks used to sit at 11 and 12: an evaluator status channel's reachability, and a
superseding `sequence`. Both read a Worker environment variable rather than anything at
runtime, so neither could ever fire in production, and the metadata published a fail-closed
status policy the code did not keep. Both are gone. Withdrawal is now AAuth revocation,
below.

### 401 — registered `Signature-Error` codes

From the Signature Error Code registry in draft-hardt-httpbis-signature-key. Nothing
invented: `invalid_request`, `invalid_input`, `unsupported_scheme`, `invalid_jwt`,
`expired_jwt`, `invalid_signature`.

One limitation worth knowing: the registry's `unknown_key` names "key not found at
jwks_uri", but `@aauth/resource` reports that as its generic `invalid_agent_token` along
with a bad `iss`, an alg disagreement and a failed signature, and documents that callers
must branch on `code` and never on `message`. A missing `kid` therefore reports as
`invalid_jwt` — true, but less specific than the registry allows.

### Response bodies

Every error response — 401 and 403 alike — is `application/problem+json` with an `error`
member, per AAuth §Error Response Format.

On a 401 the `Signature-Error` header remains the machine-readable carrier
(§Authentication Errors), and the body's `error` repeats that header's code rather than
naming one of its own, so the two can only ever agree. A body that disagrees with the
header is read as a contradiction by anyone comparing them, which on an interop capture is
the whole audience.

Two 401 bodies name conditions the header cannot:

| `error` | |
|---------|---|
| `agent_token_required` | Nothing was presented |
| `agent_token_insufficient` | A valid agent token was presented; it does not carry what this resource requires |

The distinction matters to the agent: one says sign your request, the other says go get a
different token. A test pins them apart.

### 403 — resource-defined errors

AAuth defines no error registry for resource endpoints, so this one is this resource's own:

| `error` | |
|---------|---|
| `atf_subject_mismatch` | The claim contradicts the token carrying it |

A 403 denies after the signature verified — authentication succeeded, authorization did
not — so per AAuth §Verification it carries no `Signature-Error`, no `Accept-Signature-*`,
and no `AAuth-Requirement` either: there is nothing the agent can go and get.

`POST /revoke` has two more of its own: `403 not_token_issuer` when the signer is not the
`iss` being revoked, and `400 invalid_request` for a body missing `iss` or `jti`.

## Revocation — AAuth §Token Revocation

```http
POST /revoke
Content-Type: application/json
Signature-Key: sig=jwt;jwt="…"
Content-Digest: sha-256=:…:

{ "iss": "https://provider.example", "jti": "…", "exp": 1788775882 }
```

Under identity-based access the agent presents its agent token straight here, so the agent
provider has no record of which resources hold it. AAuth's answer is that the resource
offers somewhere to call: "a resource accepting agent tokens SHOULD therefore provide a
revocation endpoint, and where none is reached that access is bounded by the agent token
lifetime alone."

This is also what replaced the ATF status channel. The provider watches the evaluator's
feed; when a grade is withdrawn the provider pushes here. No evaluator in the request path,
and no fail-open/fail-closed question, because there is nothing to fail to reach.

- **Signed, with `content-digest` covered.** A signature that does not cover the body
  authenticates the caller and authorises nothing in particular.
- **Only the token's issuer may revoke it.** The caller's identity — its `jwks_uri` `id`,
  or its assertion's `iss` under the `jwt` scheme — must equal the `iss` in the body.
- **Keyed `(iss, jti)`**, as AAuth requires: a `jti` is unique only within its issuer.
- **`200` always, never `404`.** AAuth's `404` case assumes a recipient holding records of
  the tokens it issued. This one verifies statelessly and keeps nothing.
- **`exp` sizes the KV entry**, falling back to 24 hours. A revocation only has to outlive
  the token it names, and AAuth's request body carries no `exp` to size it from —
  [spec issue #146](https://github.com/dickhardt/AAuth/issues/146).

A revoked token is refused `401 agent_token_revoked` with the agent-token challenge and no
`Signature-Error`: the registry has no code for a revoked token, and `expired_jwt` — the
nearest — would be false. 401 and not 403, because the credential is no longer good and the
remedy is another agent token, exactly as it is for an expired one.

`node harness/revoke.mjs --url https://atf-demo.aauth.dev` runs it end to end.

## The challenge, and AAuth issue #145

Every 401 carries the bare challenge AAuth -11 §Agent Token Required specifies:

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=agent-token
Link: <https://atf-demo.aauth.dev/.well-known/aauth-resource.json>; rel="aauth-resource"
```

The challenge says an AAuth agent token is required but not **which claim it must carry**,
so the requirement lives in the metadata document, and the `aauth-resource` link relation
(§Resource Metadata Link Relation) is how an agent that arrived without discovery finds it.
One extra round trip on a first encounter; no spec change.

That gap is the general problem, filed as
[dickhardt/AAuth#145](https://github.com/dickhardt/AAuth/issues/145). The proposal there is a
single `agent-claims` parameter carrying a space-delimited String of claim URIs:

```http
AAuth-Requirement: requirement=agent-token;agent-claims="https://agentictrustframework.ai/atf"
```

A String rather than an Inner List because RFC 8941 parameter values are bare items, and
named `agent-claims` rather than `claims` because `claims` is already a `requirement` value.

A framework-specific alternative — `atf-profile` / `atf-level` parameters — is implemented
behind `ATF_CHALLENGE_CARRIER=params` and **is not shipped**. It contradicts §Agent Token
Required ("The header carries no additional parameters"), and it is the shape #145 rejects:
every trust framework wanting to be named in a challenge would mint its own parameter pair.
It exists so the encoding is tested and the comparison is concrete. If #145 lands,
`buildAtfChallenge` grows one branch.

## Configuration

| Variable | Default | |
|----------|---------|---|
| `ORIGIN` | `https://atf-demo.aauth.dev` | Deployed identity, and the audience used when verifying tokens |
| `RESOURCE_URL` | `ORIGIN` | Overrides the published identity for local dev |
| `AGENT_PROVIDERS` | the summit provider | Comma-separated trusted issuers |
| `ATF_CHALLENGE_CARRIER` | `bare` | `bare` or `params` |
| `AGENT_PROVIDER_JWKS` | — | **Dev only.** `{ "<iss>": { "keys": [...] } }`, serving discovery for a provider whose origin does not resolve |
| `ATF_SUPERSEDED` | — | `[{ "appraisal_subject": "…", "sequence": N }]` |
| `ATF_STATUS` | — | `unreachable` simulates a dead status channel |

`ORIGIN` and `RESOURCE_URL` are separate because AAuth server identifiers MUST be HTTPS and
`verifyToken` refuses anything else, so a local dev origin can never be one. Nothing is
weakened by the split: an agent token carries no `aud`, so for agent identity access the
value is never compared against anything.

## Running it locally

Everything needed is in this repository. No network, no agent provider you do not control,
and no second party.

```bash
npm install
npm run harness   # stand up a local AP, mint the four tokens, write .dev.vars
npm run dev       # wrangler dev on :8787

node client.mjs --case=valid    --url http://localhost:8787/agent/echo
node client.mjs --case=tampered --url http://localhost:8787/agent/echo
node client.mjs --case=no-atf   --url http://localhost:8787/agent/echo
node client.mjs --case=expired  --url http://localhost:8787/agent/echo   # wait ~2 min first
node client.mjs --case=none     --url http://localhost:8787/agent/echo
node client.mjs --case=valid    --url http://localhost:8787/api/summarize
```

`harness/setup.mjs` runs the summit's own `provider.mjs` (a copy, with a `--no-atf` flag
added — see the note at the top of `harness/provider.mjs`) against a freshly generated key.
The appraisal is the committed evaluator output from the summit repo with its window moved
onto the current clock, which invalidates the evaluator's signature over it. That is
expected, not a bug: nothing here verifies that signature, which is precisely what "the
provider asserts the grade" means.

`transcript.txt` is a captured run — actual bytes, regenerated, never hand-edited.

```bash
npm test        # vitest in workerd
npm run typecheck
```

### The agent side is fifteen lines

`client.mjs` is the whole of it. For agent identity access there is no person server, no
challenge loop and nothing to obtain:

```js
import { fetch as sign } from '@hellocoop/httpsig'

const { response, sent } = await sign('https://atf-demo.aauth.dev/agent/echo', {
  method: 'GET',
  signingKey: agentPrivateJwk,                    // private/agent-key.pem, as a JWK
  signatureKey: { type: 'jwt', jwt: agentToken }, // out/agent-token.jwt
  components: ['@method', '@authority', '@path', 'signature-key'],
  returnSent: true,
})
```

`returnSent: true` hands back the exact request that went on the wire, which is what makes a
transcript evidence rather than description. `dryRun: true` produces it without sending.

`provider.mjs` writes the agent key as a PKCS#8 PEM; `httpsig` wants a JWK:

```js
crypto.createPrivateKey(pem).export({ format: 'jwk' })  // then add alg: 'Ed25519'
```

### Two things that will bite

**Do not narrow `supportedAlgorithms`.** The summit agent provider signs Ed25519 and the
GitHub Pages provider at `dickhardt.github.io` signs ES256. Both must verify, so the
verifier keeps the library's full default set.

**`@authority` is a covered component.** The custom-domain route lives under
`[env.production]` rather than at the top level of `wrangler.toml`: `wrangler dev` rewrites
the request authority to a top-level route pattern, so the worker would see
`atf-demo.aauth.dev` while the client signed `localhost:8787`, and every signature would
fail to verify with no useful error. Deploy with `--env production`. The same hazard applies
to any proxy that rewrites `Host`.

## Deployment

Deployed to Cloudflare Workers as `atf-demo-aauth-dev-production`, on the custom domain
`atf-demo.aauth.dev`.

```bash
npm run deploy   # wrangler deploy --env production
```

No secret to set: this resource holds no key. `--env production` is not optional — see the
`@authority` note above.

### What is verified in production

All four cases, plus the person-token challenge. `transcript.txt` is that run.

No agent provider is deployed to make it possible. `npm run harness -- --enclave` mints as
`https://dickhardt.github.io`, whose discovery document and JWKS have been published since
June and name a key whose private half is in that machine's Secure Enclave. The deployed
resource resolves `{iss}/.well-known/{dwk}` over the public internet, checks the document's
`issuer` against the identity it was fetched under, selects the key by `kid`, and verifies
an ES256 signature. The whole discovery path runs for real against a static file that was
already there.

That root key is ES256 while the summit provider's is Ed25519 — the reason
`supportedAlgorithms` is never narrowed.

What this does not prove is interoperability: one party mints and verifies. That is Imran's
provider signing and this resource verifying, and nothing here substitutes for it. The
summit provider's discovery and JWKS were checked directly and are correctly shaped
(`issuer` matches, the key carries a `kid` and a fully-specified `alg`), so the leg the live
interop run depends on is known good.

## Tech stack

- [Cloudflare Workers](https://workers.cloudflare.com/) with [Hono](https://hono.dev/)
- [`@aauth/resource`](https://www.npmjs.com/package/@aauth/resource) /
  [`@aauth/protocol`](https://www.npmjs.com/package/@aauth/protocol) for token verification
  and header formats
- [`@hellocoop/httpsig`](https://www.npmjs.com/package/@hellocoop/httpsig) for RFC 9421 HTTP
  Message Signatures and RFC 8941 structured fields

## What this does not establish

- It is not CSA certification or endorsement.
- The ATF profile is drafted for this exercise from ATF v0.9.1 and is not CSA-ratified.
- The subject binding is a proposal (interface contract, D-05). What is checked is that the
  agent provider did not contradict itself, not that an AAuth identifier and a TRACE subject
  are the same principal.
- A qualifying level is eligibility for consideration. It is not permission, and it is not a
  safety claim.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
