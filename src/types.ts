export interface Env {
  ORIGIN: string // deployed identity, from wrangler.toml [vars]
  RESOURCE_URL?: string // overrides ORIGIN (local dev, tests)

  /** Comma-separated agent provider issuers this resource trusts. */
  AGENT_PROVIDERS?: string

  /**
   * Dev-only escape hatch. A JSON object mapping an agent provider issuer to
   * the JWKS it would publish at `{iss}/.well-known/{dwk}`:
   *
   *   { "https://ap.local": { "keys": [ … ] } }
   *
   * When an issuer appears here, key discovery is served from this map instead
   * of over the network — the only way to verify a token from a local AP whose
   * origin does not resolve. Absent the override, discovery works normally.
   * Never set in production.
   */
  AGENT_PROVIDER_JWKS?: string

  /**
   * Which carrier the 401 agent-token challenge uses for the ATF requirement.
   * `bare` (default) or `params`. See src/atf.ts — the choice is still open.
   */
  ATF_CHALLENGE_CARRIER?: string

  /**
   * Fallback lifetime, in seconds, for a revocation entry whose revoking call
   * carried no `exp`. Defaults to 24 hours. See `Config.revocationTtlSeconds`
   * and https://github.com/dickhardt/AAuth/issues/146.
   */
  REVOCATION_TTL_SECONDS?: string

  /**
   * Revoked agent tokens, keyed `revoked:{iss}\u0000{jti}`, each written with
   * a KV TTL so entries expire rather than accumulating. The value is a small
   * JSON record kept for audit; presence of the key is what refuses a token.
   */
  REVOCATIONS: KVNamespace

  EVENTS_QUEUE: Queue // bound to aauth-events queue; consumed by aauth-shipper
}

export type HonoEnv = { Bindings: Env }
