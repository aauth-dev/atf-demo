// The test agent provider's public half.
//
// A separate Worker on a separate hostname, and separate for a reason: a
// Worker cannot subrequest its own route. Served from atf-demo's worker, the
// resource's fetch of this discovery document returned 522 against itself.
//
// It publishes two static documents — the discovery metadata AAuth resolves
// at {iss}/.well-known/{dwk}, and the JWKS it points to. It holds no signing
// key and issues nothing. Tokens are minted by harness/setup.mjs on whoever
// ran it, with a key under harness/ap/ that is gitignored and never deployed.
//
// What this proves: atf-demo fetches these over the public internet, checks
// the document's `issuer` against the identity it was fetched under (RFC 8414
// §3.3), selects the key by `kid`, and verifies — the same path a token from
// any other provider takes.
//
// What it does not prove: independence. Both sides are deployed from one
// repository by one operator. A 200 here is this project verifying a
// signature it made. Interoperability is Imran's provider signing and this
// resource verifying, and nothing here substitutes for that.

import jwks from './jwks.json'

const ISSUER = 'https://ap.atf-demo.aauth.dev'

const DISCOVERY = {
  issuer: ISSUER,
  jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  name: 'atf-demo test agent provider',
  description:
    'Publishes the keys of the provider that mints test tokens for ' +
    'atf-demo.aauth.dev. Public keys only; it issues nothing.',
  documentation_uri: 'https://github.com/aauth-dev/atf-demo',
}

const json = (body) =>
  new Response(`${JSON.stringify(body, null, 2)}\n`, {
    headers: {
      'Content-Type': 'application/json',
      // A JWKS is fetched on the request path. AAuth requires verifiers to
      // cache and to respect these, and forbids refetching a given issuer
      // more than once a minute.
      'Cache-Control': 'public, max-age=300',
      'Access-Control-Allow-Origin': '*',
    },
  })

export default {
  fetch(request) {
    const { pathname } = new URL(request.url)
    if (pathname === '/.well-known/aauth-agent.json') return json(DISCOVERY)
    if (pathname === '/.well-known/jwks.json') return json(jwks)
    if (pathname === '/health') return json({ status: 'ok' })
    if (pathname === '/') return json({ ...DISCOVERY, note: 'public keys only; issues nothing' })
    return new Response('not found\n', { status: 404 })
  },
}
