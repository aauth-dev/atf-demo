import type { Context } from 'hono'
import type { HonoEnv } from './types'

const SERVICE = 'atf-demo' as const

export type EmitInput = {
  event: string
  level?: number
  msg?: string
  [k: string]: unknown
}

function requestContext(c: Context<HonoEnv>) {
  const h = c.req.raw.headers
  return {
    method: c.req.method,
    route: new URL(c.req.url).pathname,
    cf_ray: h.get('cf-ray') ?? undefined,
    client_ip: h.get('cf-connecting-ip') ?? undefined,
    user_agent: h.get('user-agent') ?? undefined,
    referer: h.get('referer') ?? undefined,
    origin: h.get('origin') ?? undefined,
  }
}

/**
 * The agent identity the request *claims*, read out of the JWT in the
 * `Signature-Key` header without verifying anything.
 *
 * Every field is suffixed `_unverified` and that is not decoration. A refusal
 * is logged before, or instead of, the issuer's signature being checked, so
 * these are values the caller chose — a forged token names whatever issuer it
 * likes. They are here because the alternative was worse: until this, a
 * `verify_failed` event carried no agent identity at all, so a refusal could
 * not be attributed to a provider even for diagnosis. Read them as "the
 * request said this", never as "this provider did that".
 *
 * The pass path emits `agent_iss` and `agent_sub` with no suffix. Those come
 * from a verified token and mean what they say.
 */
export function claimedIdentity(c: Context<HonoEnv>) {
  const header = c.req.raw.headers.get('signature-key')
  if (!header) return {}
  // `Signature-Key: sig=jwt;jwt="…"` — pull the quoted assertion out without
  // a structured-fields parse. A malformed header yields nothing, which is
  // the right answer for a diagnostic field.
  const match = /jwt="([A-Za-z0-9_.=-]+)"/.exec(header)
  if (!match) return {}
  const segment = match[1].split('.')[1]
  if (!segment) return {}
  try {
    const payload = JSON.parse(atob(segment.replace(/-/g, '+').replace(/_/g, '/'))) as Record<
      string,
      unknown
    >
    const pick = (k: string) => (typeof payload[k] === 'string' ? (payload[k] as string) : undefined)
    const atf = payload['https://agentictrustframework.ai/atf']
    const level =
      atf && typeof atf === 'object'
        ? (atf as Record<string, unknown>).level
        : undefined
    return {
      agent_iss_unverified: pick('iss'),
      agent_sub_unverified: pick('sub'),
      agent_jti_unverified: pick('jti'),
      atf_level_unverified: typeof level === 'string' ? level : undefined,
    }
  } catch {
    return {}
  }
}

function signatureHeaders(c: Context<HonoEnv>) {
  const h = c.req.raw.headers
  return {
    sig_signature: h.get('signature') ?? undefined,
    sig_signature_input: h.get('signature-input') ?? undefined,
    sig_signature_key: h.get('signature-key') ?? undefined,
    sig_signature_agent: h.get('signature-agent') ?? undefined,
    sig_accept_signature: h.get('accept-signature') ?? undefined,
  }
}

// Enqueue a structured event to the aauth-events queue without
// blocking the response. Errors are logged and swallowed — event
// emission must never break the request path.
export function emit(c: Context<HonoEnv>, input: EmitInput): void {
  const full = {
    service: SERVICE,
    timestamp: new Date().toISOString(),
    event_id: crypto.randomUUID(),
    level: 30,
    ...requestContext(c),
    ...input,
  }
  c.executionCtx.waitUntil(
    c.env.EVENTS_QUEUE.send(full).catch((err: unknown) =>
      console.error('event_emit_failed', {
        error: String(err),
        event: input.event,
      })
    )
  )
}

// Convenience wrapper for the verify_failed event, which is emitted
// from multiple sites.
export function emitVerifyFailed(
  c: Context<HonoEnv>,
  reason: string,
  extra: Record<string, unknown> = {},
): void {
  emit(c, {
    event: 'aauth.atf-demo.verify_failed',
    level: 40,
    msg: `verify failed: ${reason}`,
    failure_reason: reason,
    ...claimedIdentity(c),
    ...signatureHeaders(c),
    ...extra,
  })
}
