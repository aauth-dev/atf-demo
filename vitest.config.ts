import { defineConfig } from 'vitest/config'
import { cloudflareTest } from '@cloudflare/vitest-plugin'

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.toml' },
      miniflare: {
        bindings: {
          // Pin the identity. Without this, a developer's .dev.vars (written by
          // the harness, pointing at localhost) leaks into the test env and the
          // metadata and Link assertions drift with it.
          ORIGIN: 'https://atf-demo.aauth.dev',
          RESOURCE_URL: 'https://atf-demo.aauth.dev',
          // The tests mint tokens from https://ap.test and https://other-ap.test,
          // and serve their discovery through the mocked outbound fetch. Only
          // the first is trusted, so the other exercises the untrusted-provider
          // challenge.
          AGENT_PROVIDERS: 'https://ap.test',
          AGENT_PROVIDER_JWKS: '',
          ATF_CHALLENGE_CARRIER: 'bare',
          ATF_SUPERSEDED: '',
          ATF_STATUS: '',
        },
      },
    }),
  ],
  test: {
    include: ['test/**/*.test.ts'],
  },
})
