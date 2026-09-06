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
   * Superseded appraisal sequences, as a JSON array of
   * `{ "appraisal_subject": "…", "sequence": N }`. An appraisal whose sequence
   * is at or below the recorded one for its subject is refused — the demotion
   * invariant of the interface contract. Empty in normal operation.
   */
  ATF_SUPERSEDED?: string

  /** Set to "unreachable" to simulate a dead status channel (fail closed). */
  ATF_STATUS?: string

  EVENTS_QUEUE: Queue // bound to aauth-events queue; consumed by aauth-shipper
}

export type HonoEnv = { Bindings: Env }
