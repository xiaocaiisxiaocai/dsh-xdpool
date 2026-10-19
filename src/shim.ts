/**
 * Loopback OpenAI-compatible endpoint with multi-account failover.
 *
 * The pi-ai provider points here. Each chat request acquires an account from
 * the pool; when the upstream answers with a rate limit, the shim cools that
 * account down, takes the next one, and retries in the same request — so a
 * `429 soft_rate` never reaches the user as a turn failure.
 *
 * Security model (Host/Origin loopback checks, constant-time bearer compare,
 * random port, in-process secret, body cap, error→status mapping) follows
 * corrinehu/dsh-workbuddy-connect (MIT, Copyright (c) 2026 Corrine Hu), which
 * designed and validated it.
 *
 * @module dsh-xdpool/shim
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { Readable, Transform } from 'node:stream'
import type { WorkBuddyAccount, WorkBuddyAccountPool } from './accounts.ts'
import type { WorkBuddyCatalog } from './catalog.ts'
import { parseRateLimitReset, WorkBuddyUpstreamClient, type ChatStreamResult, type UpstreamErrorKind, type WorkBuddyRegion } from './upstream.ts'
import { compactWithSummary, estimateMessagesTokens, hardTruncate, type ChatMessage } from './context-budget.ts'
import { AggregateError, forwardAggregateStreamed, resolveAggregateProvider, type AggregateCatalog } from './aggregate.ts'
import { parseProviderModelId } from './providers.ts'
import {
  COMBO_CHANNEL,
  comboChain,
  isComboId,
  isComboRow,
  resolveComboMember,
  type ComboMember,
  type ComboModelRow,
} from './combos.ts'
import type { AggregateStore } from './store.ts'
import { paidAlternativeFor } from './siblings.ts'
import { inspectSseFrame, StreamTracker, type UsageRecorder } from './stats.ts'
import { FREE_CHANNEL, FREE_MODEL_PREFIX } from './free-catalog.ts'
export interface ShimLogger {
  info?(...args: unknown[]): void
  warn(...args: unknown[]): void
  error(...args: unknown[]): void
}
export interface WorkBuddyShim {
  ready: Promise<void>
  baseUrl(): string
  token(): string
  close(): Promise<void>
}
/**
 * Everything the aggregate lane needs to answer one request.
 *
 * Optional on {@link WorkBuddyShimOptions} because most shims are pool-only: the
 * CLI and the tests never build an aggregate catalog, and making them supply one
 * would mean threading an argument nobody reads.
 */
export interface AggregateLaneOptions {
  /** The rows currently offered, keyed by composite `providerId/modelId`. */
  catalog: AggregateCatalog
  /** Where the stored settings come from, re-read per request. */
  readStore: () => AggregateStore
}
export interface ExtraLaneOptions {
  /**
   * The免密 free lane: which rows exist right now, and where to send a turn.
   *
   * The row reader is consulted per request, exactly like the pool's catalog —
   * a roster that refreshed after startup must be servable without a restart.
   */
  free: ExtraLaneSource
}
export interface ExtraLaneSource {
  current: () => readonly { modelId: string; id: string }[]
  /**
   * Run one turn, handing back the frames to write.
   *
   * The source owns the whole upstream conversation — the session identity, the
   * wire conversion, the tool bookkeeping — and returns chat-wire SSE payloads,
   * because that is the only wire this shim's caller speaks.
   */
  run: (options: {
    modelId: string
    body: string
    signal: AbortSignal
    onFrame: (payload: string) => void
  }) => Promise<unknown>
}
export interface WorkBuddyShimOptions {
  pool: WorkBuddyAccountPool
  client: WorkBuddyUpstreamClient
  catalog: WorkBuddyCatalog
  logger?: ShimLogger
  /**
   * Restrict this shim to one gateway. Two shims run side by side — one
   * per region — and each must only ever draw accounts that belong to its
   * own gateway. Absent means "every account" (a single-region deployment).
   */
  region?: WorkBuddyRegion
  /** Max accounts to try per request before giving up. */
  maxAttempts?: number
  /**
   * Where per-call usage goes.
   *
   * Optional so the CLI and the tests can run a shim with no dashboard: they
   * assemble a pool without a panel, and forcing a recorder on them would mean
   * threading an argument nobody reads.
   */
  usageRecorder?: UsageRecorder
  /**
   * The second lane: providers the user holds a key for.
   *
   * Attached to the CN shim only. The aggregate lane is gateway-independent — it
   * has no region to filter by — so running it on both shims would expose the
   * same models twice under two provider ids, and a user who picked one would
   * have no way to tell which they were using.
   */
  aggregate?: AggregateLaneOptions
  /**
   * The third and fourth lanes: the pooled免密 gateway and the sealed co-paid
   * relay.
   *
   * Also CN-shim-only, for the aggregate lane's reason plus one of their own: a
   * second copy under the global provider id would list every model twice and
   * give the user two names for one lane.
   */
  extra?: ExtraLaneOptions
}
const REQUEST_BODY_LIMIT = 64 * 1024 * 1024
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]'])
/** HTTP status each upstream failure class surfaces as. */
const KIND_STATUS: Readonly<Record<UpstreamErrorKind, number>> = {
  hard_credit: 402,
  soft_rate: 429,
  session_dead: 401,
  not_found: 502,
  server: 502,
  client: 400,
}
function hostnameOfHost(host: string): string {
  let hostname = host.trim().toLowerCase()
  if (hostname.startsWith('[')) {
    const end = hostname.indexOf(']')
    return end === -1 ? hostname : hostname.slice(0, end + 1)
  }
  const colon = hostname.lastIndexOf(':')
  if (colon !== -1 && /^\d+$/.test(hostname.slice(colon + 1))) hostname = hostname.slice(0, colon)
  return hostname
}
/** Host must name loopback; drops DNS-rebinding attempts before routing. */
function hostIsLoopback(host: string | undefined): boolean {
  if (host === undefined || host.trim() === '') return false
  return LOOPBACK_HOSTS.has(hostnameOfHost(host))
}
/** A present Origin must be loopback; non-browser clients send none and pass. */
function originIsLoopback(origin: string | undefined): boolean {
  if (origin === undefined || origin.trim() === '') return true
  try {
    const { hostname } = new URL(origin)
    return LOOPBACK_HOSTS.has(hostname) || hostname === '::1'
  } catch {
    return false
  }
}
/** Chat POSTs must carry a JSON body type (blocks simple-request CSRF). */
function isJsonContentType(req: IncomingMessage): boolean {
  const type = req.headers['content-type']
  return typeof type === 'string' && type.trim().toLowerCase().startsWith('application/json')
}
function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) })
  res.end(payload)
}
function writeOpenAIError(res: ServerResponse, status: number, kind: string, message: string): void {
  writeJson(res, status, { error: { message, type: kind, code: kind } })
}
/** True when an upstream failure body means the request overran the model's
 *  context window (OpenAI `context_length_exceeded`, WorkBuddy code 11115 /
 *  "input length too long"). The shim answers it by compacting the conversation
 *  in place and retrying once; see `recoverFromContextOverrun`. */
function isContextTooLong(body: string): boolean {
  if (body.includes('context_length_exceeded')) return true
  if (body.includes('input length too long')) return true
  if (body.includes('"code":11115')) return true
  if (/exceeds?\s+(the\s+)?(model\s+)?context\s+(window|limit)/iu.test(body)) return true
  return false
}
/**
 * A content-free description of a request, for the log when the upstream
 * rejects it.
 *
 * `model_param_invalid` arrives with an EMPTY `param` field, so the error alone
 * says nothing about which parameter was rejected — the user is left with "the
 * request parameters do not meet the current model requirements" and no way to
 * act. Recording the shape (top-level keys, message count by role, tool count,
 * approximate prompt size) makes such a rejection diagnosable from the log.
 *
 * Deliberately SHAPE ONLY: no message content, no tool schemas, no tokens. It
 * ends up in a log file, and the conversation it describes is the user's.
 */
function requestShape(raw: string): string {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const keys = Object.keys(parsed).sort()
    const messages = Array.isArray(parsed['messages']) ? parsed['messages'] as unknown[] : []
    const byRole = new Map<string, number>()
    let chars = 0
    for (const entry of messages) {
      if (typeof entry !== 'object' || entry === null) continue
      const message = entry as Record<string, unknown>
      const role = typeof message['role'] === 'string' ? message['role'] : '?'
      byRole.set(role, (byRole.get(role) ?? 0) + 1)
      // Approximate only; the point is the ORDER of magnitude.
      chars += JSON.stringify(message['content'] ?? '').length
    }
    const roles = [...byRole.entries()].map(([role, n]) => `${role}:${n}`).join(' ')
    const tools = Array.isArray(parsed['tools']) ? parsed['tools'].length : 0
    return `keys=[${keys.join(' ')}] messages=${messages.length}${roles === '' ? '' : ` (${roles})`} `
      + `tools=${tools} contentChars=${chars}`
  } catch {
    return 'body was not parseable JSON'
  }
}
/**
 * Stable identity of the conversation a request belongs to, for `sticky`.
 *
 * The FIRST user message is the key: it is the one part of the body that does
 * not change as the history grows, so every turn of a conversation hashes the
 * same way while a new chat (with a different opening message) hashes
 * differently. Hashing rather than storing the text keeps conversation content
 * out of the pool's memory.
 *
 * Two conversations that open with the exact same message share an account —
 * rare, and harmless: it only means they share one account's prompt cache.
 */
function conversationKeyOf(raw: string): string | undefined {
  try {
    const parsed = JSON.parse(raw) as { messages?: unknown }
    if (!Array.isArray(parsed.messages)) return undefined
    for (const entry of parsed.messages) {
      if (typeof entry !== 'object' || entry === null) continue
      const message = entry as Record<string, unknown>
      if (message['role'] !== 'user') continue
      const content = typeof message['content'] === 'string'
        ? message['content']
        : JSON.stringify(message['content'] ?? '')
      return createHash('sha256').update(content).digest('hex').slice(0, 32)
    }
    return undefined
  } catch {
    return undefined
  }
}

/**
 * Map a conversation key onto the `X-Conversation-ID` the upstream is told.
 *
 * WHY A CACHE AND NOT A FRESH UUID PER REQUEST
 *
 * The gateway accepts any well-formed UUID as `X-Conversation-ID`, but the id is
 * what the upstream files a thread under. Minting a new one per request would
 * make every turn of a DSH conversation look like a brand-new upstream thread,
 * which is a lie the billing and history views would have to live with. Keying
 * off the same first-user-message hash `sticky` already uses keeps one DSH
 * conversation on one upstream thread, and a new chat on a new one.
 *
 * The map is bounded because a long-lived shim would otherwise accumulate one
 * entry per conversation forever. Eviction only costs a thread boundary.
 */
const CONVERSATION_ID_CACHE_LIMIT = 512
const conversationIds = new Map<string, string>()

function upstreamConversationId(key: string | undefined): string | undefined {
  if (key === undefined) return undefined
  const known = conversationIds.get(key)
  if (known !== undefined) {
    // Refresh insertion order so the hot conversations are the ones that survive.
    conversationIds.delete(key)
    conversationIds.set(key, known)
    return known
  }
  const minted = randomUUID()
  conversationIds.set(key, minted)
  if (conversationIds.size > CONVERSATION_ID_CACHE_LIMIT) {
    const oldest = conversationIds.keys().next()
    if (oldest.done !== true) conversationIds.delete(oldest.value)
  }
  return minted
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > REQUEST_BODY_LIMIT) {
        reject(new Error('request body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}
export function createWorkBuddyShim(options: WorkBuddyShimOptions): WorkBuddyShim {
  const { pool, client, catalog, usageRecorder } = options
  const region = options.region
  const logger = options.logger
  const aggregate = options.aggregate
  const extra = options.extra
  const maxAttempts = options.maxAttempts ?? 8
  // Per-process secret. The adapter resolves this as the OpenAI apiKey; the
  // shim never forwards it, because the real token comes from the pool.
  const SHARED_SECRET = randomBytes(32).toString('base64url')
  function bearerOk(req: IncomingMessage): boolean {
    const header = req.headers.authorization
    if (typeof header !== 'string') return false
    const match = /^Bearer\s+(.+)$/i.exec(header.trim())
    if (match === null) return false
    const a = Buffer.from(match[1] as string)
    const b = Buffer.from(SHARED_SECRET)
    if (a.length !== b.length) return false
    return timingSafeEqual(a, b)
  }
  const server: Server = createServer((req, res) => {
    void handle(req, res)
  })
  /**
   * "The same model has a paid row" sentence for a 429 body, or undefined.
   *
   * Reads the catalog the shim was built with, so the hint names a row this
   * gateway ACTUALLY serves — a CN-only id in a global 429 would be worse than
   * no hint at all. Absent when the cooling model is itself paid, or when the
   * family has no priced twin.
   */
  function paidTwinHint(modelId: string): string | undefined {
    const models = catalog.current()
    const model = models.find(candidate => candidate.id === modelId)
    if (model === undefined) return undefined
    const twin = paidAlternativeFor(model, models)
    if (twin === undefined) return undefined
    return `${twin.id} is the same model on a paid row (x${twin.multiplier.toFixed(2)} credits) `
      + 'and is rate-limited separately; switch to it to keep going'
  }
  /**
 * Replace a request's model id with the provider's own, leaving the rest of the
 * body byte-identical.
 *
 * A textual replacement rather than a re-serialise: the aggregate lane's caller
 * is pi-ai, and re-encoding its body would drop undefined-valued keys and reorder
 * nothing but risk changing numbers pi-ai deliberately rounded. Only the `model`
 * field changes, and only when it actually names the composite id.
 */
function withBareModelId(raw: string, modelId: string): string {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    parsed.model = modelId
    return JSON.stringify(parsed)
  } catch {
    // An unparseable body is the forwarder's problem to report, and it will
    // report it better than this helper can invent one here.
    return raw
  }
}
/**
 * The aggregate row a composite model id names, or undefined.
   *
   * Answering `undefined` for an id that merely LOOKS composite is the point: a
   * slash is legal in a WorkBuddy model id too, and a request naming one must
   * fall through to the pool rather than to a lane that cannot serve it.
   */
  function aggregateRowFor(modelId: string | undefined): { providerId: string; modelId: string } | undefined {
    if (aggregate === undefined || modelId === undefined) return undefined
    const parsed = parseProviderModelId(modelId)
    if (parsed === null) return undefined
    // Only a row the catalog currently offers is served. A stale picker entry —
    // a provider switched off, or a key cleared since the snapshot — must not
    // reach an upstream with a credential this shim no longer holds.
    const row = aggregate.catalog.find(modelId)
    if (row === undefined || row.providerId !== parsed.providerId || row.modelId !== parsed.modelId) return undefined
    return parsed
  }
  /**
   * The extra lane a prefixed model id names, or undefined.
   *
   * A prefixed id cannot collide with anything else: `free:` is the plugin's own
   * convention and no gateway publishes a model whose id begins with it. That is
   * why this lane can be routed on the id's PREFIX while the aggregate lane is
   * routed on a slash — no header, no extra field, and no chance of a caller
   * spoofing its way into a lane by guessing.
   *
   * A prefixed id the lane does not currently offer is reported as
   * unavailable, never routed to the pool: the pool would answer "sign in to
   * WorkBuddy" for a model it has never heard of, and the user would go looking
   * for a login that is not the problem.
   */
  function extraLaneFor(modelId: string | undefined): { source: ExtraLaneSource; modelId: string; lane: string } | undefined {
    if (modelId === undefined || extra === undefined) return undefined
    if (!modelId.startsWith(FREE_MODEL_PREFIX)) return undefined
    const source = extra.free
    if (source === undefined) return undefined
    const bare = modelId.slice(FREE_MODEL_PREFIX.length)
    // Only a row the roster currently holds is served, so a stale picker entry
    // cannot reach an upstream this shim no longer has a route for.
    if (!source.current().some(row => row.modelId === modelId || row.id === bare)) return undefined
    return { source, modelId: bare, lane: 'free' }
  }
  /** The lane that a prefixed id names even when its roster is empty. */
  function extraLaneNamed(modelId: string | undefined): string | undefined {
    if (modelId === undefined || extra === undefined) return undefined
    return modelId.startsWith(FREE_MODEL_PREFIX) ? 'free' : undefined
  }
  /**
   * Serve one extra-lane turn.
   *
   * The lane arrives here as chat completions, which is the point of the
   * translation layer: the caller never learns which of the three upstream wires
   * the row actually speaks. The source owns the whole turn — session identity,
   * body re-spelling, tool-name restoration, event folding — and hands back chat
   * payloads, so this function only frames them.
   */
  async function serveExtraCompletion(
    res: ServerResponse,
    raw: string,
    modelId: string,
    target: { source: ExtraLaneSource; modelId: string; lane: string },
    signal: AbortSignal,
  ): Promise<void> {
    const frames: string[] = []
    try {
      await target.source.run({
        modelId: target.modelId,
        body: raw,
        signal,
        onFrame: payload => frames.push(payload),
      })
    } catch (error: unknown) {
      if (res.headersSent) {
        res.end()
        return
      }
      const kind = error instanceof AggregateError ? error.kind : 'server'
      const message = error instanceof AggregateError ? error.message : error instanceof Error ? error.message : String(error)
      writeOpenAIError(res, KIND_STATUS[kind], `${target.lane}_${kind}`, message)
      return
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    })
    // Always one terminating frame, even when the upstream sent nothing: a
    // decoder that sees no `[DONE]` reads a finished turn as a stream the
    // gateway cut, which the host answers with a retry.
    for (const payload of frames) res.write(`data: ${payload}\n\n`)
    res.write('data: [DONE]\n\n')
    res.end()
  }
  /**
   * Serve one aggregate turn: forward to the provider, stream back verbatim.
   *
   * No account rotation and no compaction retry. The first is honest — the key
   * belongs to the user and the lane has no other credential to fall back to. The
   * second is out of scope here: compaction is the pool's response to ONE
   * gateway's window, and a third-party window differs per provider, so silently
   * halving a conversation to satisfy one would corrupt the others' turns.
   */
  async function serveAggregateCompletion(
    res: ServerResponse,
    raw: string,
    modelId: string,
    parsed: { providerId: string; modelId: string },
    signal: AbortSignal,
  ): Promise<void> {
    const store = aggregate?.readStore()
    if (store === undefined) {
      writeOpenAIError(res, 503, 'aggregate_off', 'the aggregate lane is not available on this profile')
      return
    }
    let resolved: ReturnType<typeof resolveAggregateProvider>
    try {
      resolved = resolveAggregateProvider(store, parsed.providerId)
    } catch (error: unknown) {
      // A provider that is switched off, missing a key, or carrying a placeholder
      // base URL is a SETTINGS state, not a transport fault. `client` maps to 400,
      // which is the honest status: retrying cannot help.
      const message = error instanceof Error ? error.message : String(error)
      writeOpenAIError(res, error instanceof AggregateError ? KIND_STATUS[error.kind] : 400, 'aggregate_config', message)
      return
    }
    // The bare model id travels to the provider, never the composite one: no
    // registry publishes a model called `openai/gpt-4.1`.
    const body = withBareModelId(raw, parsed.modelId)
    const frames: string[] = []
    try {
      await forwardAggregateStreamed(resolved, parsed.modelId, body, {
        signal,
        onData: payload => frames.push(payload),
      })
    } catch (error: unknown) {
      if (res.headersSent) {
        res.end()
        return
      }
      if (error instanceof AggregateError) {
        writeOpenAIError(res, KIND_STATUS[error.kind], `aggregate_${error.kind}`, error.message)
        return
      }
      writeOpenAIError(res, 500, 'aggregate_internal', error instanceof Error ? error.message : String(error))
      return
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    })
    for (const payload of frames) res.write(`data: ${payload}\n\n`)
    res.write('data: [DONE]\n\n')
    res.end()
  }
  const ready = new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve())
    server.once('error', reject)
  })
  server.listen(0, '127.0.0.1')
  const baseUrl = (): string => {
    const address = server.address()
    if (address === null || typeof address === 'string') {
      throw new Error('workbuddy shim has no listening address')
    }
    return `http://127.0.0.1:${address.port}`
  }
  /**
   * Last balance refresh per account, so a busy account is not probed on
   * every request. Ten minutes is well inside the window where ordinary use
   * could cross a reserve.
   */
  const lastBalanceAt = new Map<string, number>()
  const BALANCE_REFRESH_MS = 10 * 60 * 1000
  /**
   * Refresh one account known credit balance, best effort.
   *
   * Runs in the background after a successful request. Failures are swallowed
   * on purpose: a reserve is a safety feature, and a flaky balance lookup must
   * never become a failed user request or a noisy log.
   */
  async function refreshBalance(account: WorkBuddyAccount): Promise<void> {
    const now = Date.now()
    const last = lastBalanceAt.get(account.id) ?? 0
    if (now - last < BALANCE_REFRESH_MS) return
    lastBalanceAt.set(account.id, now)
    try {
      const credits = await client.fetchCredits(account.credential)
      // The expiry travels with the balance: `expiry` mode sorts on it, and a
      // balance read is the only place we ever learn it.
      pool.noteCredits(account.id, credits.total, credits.nearestExpiryMs)
    } catch {
      // Keep the previous reading; the next request tries again.
    }
  }
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (!hostIsLoopback(req.headers.host)) {
        writeOpenAIError(res, 403, 'host_not_allowed', 'Host header must name the loopback interface')
        return
      }
      if (!originIsLoopback(req.headers.origin)) {
        writeOpenAIError(res, 403, 'origin_not_allowed', 'Origin must be a loopback origin')
        return
      }
      if (!bearerOk(req)) {
        writeOpenAIError(res, 401, 'unauthorized', 'missing or invalid Authorization bearer')
        return
      }
      const url = req.url ?? '/'
      if (req.method === 'GET' && (url === '/healthz' || url === '/healthz/')) {
        writeJson(res, 200, { ok: true, pool: pool.status() })
        return
      }
      if (req.method === 'GET' && (url === '/v1/models' || url === '/v1/models/')) {
        // Both lanes answer here. A composite id can only come from the
        // aggregate lane, so listing one is the honest answer to "what does this
        // provider serve" — and the pool lane keeps listing its own rows.
        const rows: { id: string; object: string; created: number; owned_by: string }[] = catalog.current().map(model => ({
          id: model.id,
          object: 'model',
          created: 0,
          owned_by: 'workbuddy',
        }))
        if (aggregate !== undefined) {
          for (const row of aggregate.catalog.current()) {
            // A chain has no vendor of its own; naming it after its first
            // member would claim a provider the chain is not bound to, and
            // `combo:` says plainly that this is a route over other rows.
            const ownedBy = isComboRow(row) ? COMBO_CHANNEL : row.providerId
            rows.push({ id: row.id, object: 'model', created: 0, owned_by: ownedBy })
          }
        }
        // The two extra lanes list under their OWN channel tag, never under the
        // shim's owner: a `free:` row served here is not WorkBuddy traffic, and
        // the `owned_by` field is what a client reads to tell them apart.
        if (extra !== undefined) {
          for (const row of extra.free.current()) {
            rows.push({ id: row.modelId, object: 'model', created: 0, owned_by: FREE_CHANNEL })
          }
        }
        writeJson(res, 200, { object: 'list', data: rows })
        return
      }
      if (req.method === 'POST' && (url === '/v1/chat/completions' || url === '/v1/chat/completions/')) {
        await chatCompletions(req, res)
        return
      }
      writeOpenAIError(res, 404, 'not_found', `no such route: ${req.method} ${url}`)
    } catch (error: unknown) {
      if (!res.headersSent) writeOpenAIError(res, 500, 'internal', String(error))
      else res.end()
    }
  }
  /**
   * Serve one turn through a combo chain, trying its members in order.
   *
   * The point of a chain is that the members are NOT interchangeable: one is
   * rate-limited, another is out of credit, a third has no key. So every member
   * gets its own lane, and a member that fails is recorded as a member failure —
   * never as "the chain failed", which would leave the user with no way to tell a
   * broken member from an exhausted one.
   *
   * Mixed chains are the interesting case. A chain may name a pool model AND a
   * composite third-party model, and those two speak different wires: the pool
   * needs `prepareChatBody` plus account rotation, the aggregate lane needs the
   * bare provider model id and no rotation. Both are prepared from the caller's
   * ORIGINAL body rather than from each other's output, so nothing one member
   * needs (`developer` role, `tool_choice`) reaches a third-party provider, and
   * nothing a third-party provider returns can be mistaken for the pool's shape.
   */
  async function serveComboCompletion(
    res: ServerResponse,
    raw: string,
    row: ComboModelRow,
    signal: AbortSignal,
  ): Promise<void> {
    const store = aggregate?.readStore()
    const sources = {
      pool: catalog.current(),
      aggregate: aggregate === undefined ? [] : aggregate.catalog.providerRows(),
    }
    const members = comboChain(row)
      .map(modelId => resolveComboMember(modelId, sources))
      .filter((member): member is ComboMember => member !== undefined)
    if (members.length === 0) {
      // Reachable only if a chain row survived a refresh whose members have all
      // since gone away. Answering "no member" names the real problem; the
      // alternative — falling through to the pool — would send `combo:x` to a
      // gateway that has never heard of it.
      writeOpenAIError(res, 503, 'combo_empty', `chain ${row.id} has no member model available right now`)
      return
    }
    const attempts: string[] = []
    let last: { kind: string; status: number; message: string } | undefined
    for (const member of members) {
      if (signal.aborted) return
      attempts.push(member.modelId)
      // A member with no key is a settings problem the user can fix, and
      // `resolveAggregateProvider` below names it as such — so it is not
      // pre-judged here, where the only available answer would be a guess.
      if (!member.aggregate) {
        // Pool member: one account, one attempt. Account rotation inside a chain
        // member would double the attempts and could consume the whole budget on
        // one member, which defeats the chain's reason to exist.
        const account = await pool.acquire(member.modelId, region)
        if (account === undefined) {
          const why = pool.unavailableReason(member.modelId, region)
          last = {
            kind: why.reason,
            status: why.reason === 'cooling' ? 429 : 401,
            message: `member ${member.modelId} has no usable WorkBuddy account (${why.reason})`,
          }
          continue
        }
        const prepared = client.prepareChatBody(raw)
        const result = await client.chatStream(
          account.credential,
          prepared,
          signal,
          upstreamConversationId(conversationKeyOf(raw)),
        )
        if (result.ok) {
          const turnId = randomBytes(8).toString('hex')
          await serveSuccessfulStream(
            res,
            account,
            result,
            logger,
            refreshBalance,
            pool,
            usageRecorder === undefined
              ? undefined
              : { recorder: usageRecorder, region: region ?? 'cn', model: member.modelId, turnId },
          )
          return
        }
        last = { kind: result.kind, status: result.status, message: result.message }
        if (result.kind === 'soft_rate') pool.penalize(account.id, parseRateLimitReset(result.message), member.modelId)
        else if (result.kind === 'session_dead') pool.penalizeCredentialDead(account.id)
        else if (result.kind === 'hard_credit') pool.penalizeExhausted(account.id)
        continue
      }
      if (store === undefined || aggregate === undefined) {
        last = { kind: 'combo_config', status: 503, message: 'the aggregate lane is not available on this profile' }
        continue
      }
      const parsed = parseProviderModelId(member.modelId)
      if (parsed === null) {
        last = { kind: 'combo_config', status: 400, message: `member ${member.modelId} is not a valid provider model id` }
        continue
      }
      let resolved: ReturnType<typeof resolveAggregateProvider>
      try {
        resolved = resolveAggregateProvider(store, parsed.providerId)
      } catch (error: unknown) {
        last = {
          kind: 'combo_config',
          status: 400,
          message: error instanceof Error ? error.message : String(error),
        }
        continue
      }
      const frames: string[] = []
      try {
        await forwardAggregateStreamed(resolved, parsed.modelId, withBareModelId(raw, parsed.modelId), {
          signal,
          onData: payload => frames.push(payload),
        })
      } catch (error: unknown) {
        const kind = error instanceof AggregateError ? error.kind : 'server'
        last = {
          kind,
          status: error instanceof AggregateError ? KIND_STATUS[error.kind] : 502,
          message: error instanceof Error ? error.message : String(error),
        }
        continue
      }
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      })
      for (const payload of frames) res.write(`data: ${payload}\n\n`)
      res.write('data: [DONE]\n\n')
      res.end()
      return
    }
    // Every member declined. The honest report is the LAST member's class plus
    // the whole attempt list: a chain of one rate-limited member must not read
    // as "no credential", and a chain of three silently-empty ones must not read
    // as one model's 401.
    const kind = last?.kind ?? 'combo_empty'
    const status = last?.status ?? 503
    writeOpenAIError(
      res,
      status,
      `combo_${kind}`,
      `chain ${row.id}: no member answered after ${attempts.length} [${attempts.join(' → ')}]`
        + `: ${(last?.message ?? 'no member was reachable').slice(0, 300)}`,
    )
  }
  /**
   * Serve one chat completion, rotating accounts on rate limits.
   *
   * A rate-limited account is cooled for exactly the window the upstream
   * reports (when parseable) and the next account is tried immediately, so a
   * pool with any healthy member never surfaces a 429 to the caller.
   */
  async function chatCompletions(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!isJsonContentType(req)) {
      writeOpenAIError(res, 415, 'unsupported_media_type', 'Content-Type must be application/json')
      return
    }
    const raw = (await readBody(req)).toString('utf8')
    const controller = new AbortController()
    req.on('close', () => controller.abort())
    // The request's target model. Read BEFORE any WorkBuddy preparation: the
    // aggregate lane speaks a different wire and must see the caller's body
    // untouched, and `prepareChatBody` rewrites it for the WorkBuddy gateway.
    let modelId: string | undefined
    try {
      const parsed = JSON.parse(raw) as { model?: unknown }
      modelId = typeof parsed.model === 'string' && parsed.model !== '' ? parsed.model : undefined
    } catch {
      modelId = undefined
    }
    // Two lanes, decided by the model id's own shape: the aggregate lane
    // advertises composite `providerId/modelId` ids and nothing else does, so the
    // split needs no extra header and cannot be spoofed by a caller that guessed
    // a slash. A chain id (`combo:<slug>`) is checked FIRST and can never be
    // mistaken for either: it has no slash, so the composite parse rejects it.
    const comboRow = aggregate === undefined || modelId === undefined
      ? undefined
      : aggregate.catalog.findCombo(modelId)
    if (comboRow !== undefined) {
      await serveComboCompletion(res, raw, comboRow, controller.signal)
      return
    }
    // A `combo:` id that no longer resolves — the chain was disabled, or every
    // member left the roster — must NOT fall through to the pool. It has no
    // slash, so the pool would report "not signed in" for a lane that never had
    // a credential problem, and the user would go looking at their login.
    if (modelId !== undefined && isComboId(modelId)) {
      writeOpenAIError(
        res,
        503,
        'combo_missing',
        `chain ${modelId} is not available right now; edit or re-enable it in XD Pool → Routing`,
      )
      return
    }
    const aggregateRow = aggregateRowFor(modelId)
    if (aggregateRow !== undefined) {
      await serveAggregateCompletion(res, raw, modelId as string, aggregateRow, controller.signal)
      return
    }
    // The pooled免密 and sealed co-paid lanes are decided by the id PREFIX. They
    // are checked after the aggregate lane on purpose: neither id shape contains
    // a slash the composite parse would accept, so the order is a readability
    // choice, not a correctness one — but a prefix check placed first would have
    // to run on every pool request.
    const extraTarget = extraLaneFor(modelId)
    if (extraTarget !== undefined) {
      await serveExtraCompletion(res, raw, modelId as string, extraTarget, controller.signal)
      return
    }
    const lane = extraLaneNamed(modelId)
    if (lane !== undefined) {
      // A prefixed id whose roster is empty — the listing failed, the model was
      // withdrawn, or the co-paid lane has no sealed credential on this build —
      // must NOT fall through to the pool. The pool would report "not signed in"
      // for a lane that never had a WorkBuddy problem, and the user would go
      // looking for a login that is not the reason.
      writeOpenAIError(
        res,
        503,
        `${lane}_unavailable`,
        lane === 'free'
          ? `${modelId as string} is not available right now; the free lane's model listing is refreshed on the XD Pool card`
          : `${modelId as string} is not available right now; sign in to the co-paid lane on the XD Pool card`,
      )
      return
    }
    const prepared = client.prepareChatBody(raw)
    // `sticky` binds each conversation to one account; the pool ignores this
    // under every other distribution.
    const conversationKey = conversationKeyOf(raw)
    // `modelId` is already read above, before the lane split. It doubles as the
    // cooldown key because the upstream rate limit is per-model ("可切换其他模型
    // 继续使用"): a 429 on `hy4-preview` only cools that model on the account,
    // never the whole one.
    const tried: string[] = []
    let last: { kind: UpstreamErrorKind; status: number; message: string } | undefined
    // One identity per user request, minted once, so every account the pool
    // rotates through - and the compaction retry below - file under the SAME
    // turn. Counting those separately would overstate how much the user asked
    // for, which is the one number a usage panel must never inflate.
    const turnId = randomBytes(8).toString('hex')
    const usageContext: UsageContext | undefined = usageRecorder === undefined
      ? undefined
      : { recorder: usageRecorder, region: region ?? 'cn', model: modelId ?? '(none)', turnId }
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      if (controller.signal.aborted) return
      const account = await pool.acquire(modelId, region, conversationKey)
      if (account === undefined) {
        // Ask the POOL why, instead of inferring it from this request alone.
        //
        // The old check used a flag set earlier IN THIS LOOP, which cannot see a
        // cooldown that was established by an earlier request. After a 429, the
        // next request found no account on its first attempt, the flag was still
        // false, and the shim answered 401 "no credential found; sign in" — so
        // DSH showed an "API key invalid" panel for a model that was merely
        // cooling, sending the user to re-authenticate over a temporary limit.
        const why = pool.unavailableReason(modelId, region)
        if (why.reason === 'cooling') {
          // A rate limit is TEMPORARY: the caller should wait, not re-authenticate.
          const subject = modelId === undefined
            ? 'every WorkBuddy account is rate-limited'
            : `every account is rate-limited for model ${modelId}`
          const upstream = last === undefined ? '' : ` — ${last.message.slice(0, 200)}`
          // The gateway limits each ROW of a product line separately, so a
          // cooling free row usually has a working paid twin. Without this the
          // user's only move is to wait; naming the twin gives them a way out
          // that costs a little rather than nothing.
          const twin = modelId === undefined ? undefined : paidTwinHint(modelId)
          writeOpenAIError(
            res,
            429,
            'soft_rate',
            `${subject} (${why.cooling}/${why.total} cooling, tried ${tried.length})`
              + `${tried.length === 0 ? '' : `: ${tried.join(' → ')}`}${upstream}`
              + (twin === undefined ? '' : ` — ${twin}`),
          )
          return
        }
        if (why.reason === 'disabled') {
          writeOpenAIError(
            res,
            403,
            'no_enabled_account',
            `all ${why.total} WorkBuddy account(s) for this gateway are switched off or ignored; `
              + 're-enable one on the pool card',
          )
          return
        }
        if (why.reason === 'reserve') {
          writeOpenAIError(
            res,
            402,
            'reserve_floor',
            `every WorkBuddy account is at or below its credit reserve (${why.total} account(s)); `
              + 'lower the reserve on the pool card or top up credits',
          )
          return
        }
        if (why.reason === 'session_dead') {
          // Distinct from "never signed in": these accounts HAVE credentials, the
          // upstream just refuses them now. Waiting does not help, and saying
          // "no credential found" would send the user looking for a missing file.
          writeOpenAIError(
            res,
            401,
            'session_dead',
            `${why.dead}/${why.total} WorkBuddy account(s) for this gateway were rejected by the upstream `
              + '(their sign-in was revoked); sign in again in the WorkBuddy desktop app to restore them',
          )
          return
        }
        writeOpenAIError(
          res,
          401,
          'not_signed_in',
          why.total === 0
            ? 'no WorkBuddy credential found for this gateway; sign in on the desktop app (or set WORKBUDDY_AUTH_FILE)'
            : `no usable WorkBuddy credential among ${why.total} account(s) for this gateway; sign in again on the desktop app`,
        )
        return
      }
      tried.push(account.label)
      const result = await client.chatStream(
        account.credential,
        prepared,
        controller.signal,
        upstreamConversationId(conversationKey),
      )
      if (result.ok) {
        // Success is filed by the stream forwarder, the only place that knows
        // when the stream really ended and what it cost.
        await serveSuccessfulStream(res, account, result, logger, refreshBalance, pool, usageContext)
        return
      }
      // A refusal is filed here because there is no stream to time: the call
      // left the machine and came back refused. Note the early return above,
      // where `pool.acquire` found nothing, records NOTHING - under-reporting
      // one turn beats claiming a request that was never sent.
      usageRecorder?.record({
        region: region ?? 'cn',
        model: modelId ?? '(none)',
        account: account.label,
        turnId,
        at: Date.now(),
        ok: false,
      })
      last = { kind: result.kind, status: result.status, message: result.message }
      // A dead session is only recoverable when the refresh token still works.
      // `refreshAccount` asks the upstream and reports back: `true` means the
      // token was renewed (retry the request), `false` means the upstream
      // confirmed the credential is revoked. In that case the account is cooled
      // so the next attempt rotates instead of landing on it again — without
      // this, every one of `maxAttempts` hit the same dead account while healthy
      // accounts were never tried.
      if (result.kind === 'session_dead') {
        logger?.warn(`dsh-xdpool: ${account.label} session dead; refreshing token and retrying`)
        const before = account.credential.accessToken
        const recovered = await pool.refreshAccount(account.id, { force: true })
        // A 401 on a token the upstream still hands out refresh credentials for
        // is only "maybe stale". Once the refresh comes back with the SAME token
        // (or fails outright) there is nothing left to try: treat it as dead so
        // the retry budget goes to the other accounts instead of this one.
        if (!recovered || account.credential.accessToken === before) {
          pool.penalizeCredentialDead(account.id)
          logger?.warn(
            `dsh-xdpool: ${account.label} sign-in is no longer valid `
              + `(attempt ${attempt + 1}/${maxAttempts}); rotating`,
          )
        }
        continue
      }
      // Credit exhaustion is an ACCOUNT condition, not a model one: every model on
      // that account is dead until its quota resets, so cool the whole account and
      // rotate. Failing the request here would waste the other healthy accounts.
      if (result.kind === 'hard_credit') {
        pool.penalizeExhausted(account.id)
        logger?.warn(
          `dsh-xdpool: ${account.label} has no credits left `
            + `(attempt ${attempt + 1}/${maxAttempts}); rotating`,
        )
        continue
      }
      // A `client` failure (HTTP 400) names no parameter when the upstream
      // leaves `extError.param` empty, which is the usual case — the user then
      // gets "the request parameters do not meet the current model requirements"
      // and nothing else. Log the SHAPE of what we sent (keys and counts only,
      // never message content) so the next occurrence is diagnosable from the
      // log instead of requiring a reproduction.
      if (result.kind === 'client') {
        logger?.warn(
          `dsh-xdpool: ${account.label} rejected the request as invalid `
          + `(model ${modelId ?? '(none)'}) — ${requestShape(raw)}; upstream: ${result.message.slice(0, 300)}`,
        )
      }
      // Other failures are terminal for this request.
      if (result.kind !== 'soft_rate') break
      // Cool only this model on this account; the account's other models stay
      // usable (the upstream explicitly allows switching to another model).
      pool.penalize(account.id, parseRateLimitReset(result.message), modelId)
      logger?.warn(
        `dsh-xdpool: ${account.label} rate-limited on ${modelId ?? '(no model)'} ` +
          `(attempt ${attempt + 1}/${maxAttempts}); rotating`,
      )
    }
    if (last === undefined) {
      writeOpenAIError(res, 500, 'internal', 'chat request exhausted without a result')
      return
    }
    // A context-window overrun has two layers of defence, and this is the inner
    // one. The Harness runs its own `compaction-basic` BEFORE dispatch, driven by
    // the context window each model advertises — but that window is a guess for
    // an upstream routed through a shim, so a prompt can still arrive too large.
    // When it does, compact in place here and retry once; if even that cannot fit,
    // emit the message the Harness classifies as an overflow (see
    // `contextOverflowMessage`) so its OUTER recovery path gets a chance to
    // shrink the history and retry at the agent level.
    //
    // The two layers are complementary, not redundant: this one keeps a single
    // turn alive without the Harness ever seeing a failure, and the outer one
    // survives the case where a shim-side compaction still will not fit.
    if (isContextTooLong(last.message)) {
      const recovered = await recoverFromContextOverrun({
        raw,
        modelId,
        controller,
        region,
        logger,
        client,
        pool,
        maxAttempts,
        usage: usageContext,
        contextWindow: modelId === undefined
          ? undefined
          : catalog.current().find(m => m.id === modelId)?.contextWindow,
      })
      if (recovered.ok) {
        await serveSuccessfulStream(res, recovered.account, recovered.result, logger, refreshBalance, pool, usageContext)
        return
      }
      // The wording is a contract with the Harness; see `contextOverflowMessage`.
      writeOpenAIError(res, 400, 'context_length_exceeded', contextOverflowMessage(modelId, recovered.detail))
      return
    }
    writeOpenAIError(
      res,
      KIND_STATUS[last.kind],
      last.kind,
      `workbuddy upstream ${last.kind} (http ${last.status}) after ${tried.length} account(s) [${tried.join(' → ')}]: ${last.message.slice(0, 400)}`,
    )
  }
  return {
    ready,
    baseUrl,
    token: () => SHARED_SECRET,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close(() => resolve())
        server.closeAllConnections()
        server.once('error', reject)
      }),
  }
}
/**
 * Build the overflow message the Harness must recognize.
 *
 * This is deliberately NOT free-form prose. `dsh-compaction-basic` decides
 * whether to compact-and-retry by running the text that reaches it through
 * `isContextWindowExceededError()` (`@deepseek-ai/dsh-llm`), whose matcher
 * accepts only specific phrasings:
 *
 *   - `context_length_exceeded` / `context window exceeded`
 *   - `maximum context length`
 *   - `<input|prompt|request|messages> too large|long for ... context`
 *   - `<input|prompt|request> exceeds the ... context window`
 *
 * The obvious friendly sentence ("the conversation exceeds this model's
 * context window") matches NONE of them, and neither does the WorkBuddy
 * upstream's own "input length too long" / code 11115. Emitting either meant
 * the Harness saw an unclassifiable 400, skipped its recovery path, and
 * surfaced a dead turn — the bug this function exists to prevent.
 *
 * The leading clause carries the machine-matched wording; the trailing clause
 * is what a human reads. Keep both in sync with
 * `tests/context-overflow-contract.test.ts`.
 */
export function contextOverflowMessage(modelId: string | undefined, detail = ''): string {
  const subject = modelId === undefined ? 'the model' : `model ${modelId}`
  const note = detail === '' ? '' : ` (${detail})`
  return `This model's maximum context length was exceeded: the prompt is too large for `
    + `${subject}, and the conversation could not be compacted in place${note}. `
    + `Compact the conversation, or start a new chat.`
}
/**
 * Where one SSE frame ends inside a buffer.
 *
 * Both offsets come back because a frame's CONTENT ends before its SEPARATOR
 * does: the stripper inspects the content to decide whether the frame is the
 * gateway's usage trailer, while the host still needs the separator to keep
 * the stream well-formed.
 */
function frameSpan(buf: Buffer): { contentEnd: number; frameEnd: number } | undefined {
  const bare = buf.indexOf('\n\n')
  const crlf = buf.indexOf('\r\n\r\n')
  if (bare === -1 && crlf === -1) return undefined
  if (crlf !== -1 && (bare === -1 || crlf < bare)) return { contentEnd: crlf, frameEnd: crlf + 4 }
  return { contentEnd: bare, frameEnd: bare + 2 }
}
/**
 * The identity one logical turn is filed under, plus where its calls land.
 *
 * Shared by the first try and by the context-overrun retry on purpose: compacting
 * and sending again is another PHYSICAL call for the SAME user request, and
 * billing it as a second turn would overstate how much the user asked for.
 */
interface UsageContext {
  recorder: UsageRecorder
  /** `cn` or `global`; the panel groups by gateway. */
  region: string
  /** The model id the request asked for. */
  model: string
  /** Identifies the user request, shared across retries. */
  turnId: string
}
/**
 * Serve one already-successful upstream stream as an SSE response.
 *
 * Extracted so the context-overrun recovery path reuses the exact same
 * bookkeeping (noteServed + background balance refresh) as a first-try hit.
 *
 * The usage trailer is stripped here rather than never requested: the panel is
 * built from those numbers, so asking for them and then dropping the frames the
 * host did not ask for costs one filter and keeps the forwarded stream
 * byte-identical to what the host would have received without it.
 */
async function serveSuccessfulStream(
  res: ServerResponse,
  account: WorkBuddyAccount,
  result: Extract<ChatStreamResult, { ok: true }>,
  logger: ShimLogger | undefined,
  refreshBalance: (account: WorkBuddyAccount) => Promise<void>,
  pool: WorkBuddyAccountPool,
  usage: UsageContext | undefined,
): Promise<void> {
  logger?.info?.(`dsh-xdpool: served by ${account.label}`)
  // Only now is this account the one actually serving the user: a request
  // that failed over to another account must not mark the tried one as used.
  pool.noteServed(account.id)
  // Refresh the balance in the background so the reserved-credit floor has a
  // fresh reading. Deliberately NOT awaited: the response is already ready and
  // a balance lookup must never delay the user's stream.
  void refreshBalance(account)
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  })
  const tracker = new StreamTracker(Date.now())
  let recorded = false
  /**
   * File this call exactly once.
   *
   * Reached from the filter's flush AND from the upstream error handler, and an
   * upstream stream that dies mid-flight can reach both, so the flag is what
   * keeps one physical call from being counted twice. A stream that broke is
   * recorded as failed: the host got a 200 and then an answer that stops
   * halfway, which is a failed turn from the user's side of the wire.
   */
  const finish = (ok: boolean): void => {
    if (recorded) return
    recorded = true
    if (usage?.recorder === undefined) return
    usage.recorder.record({
      region: usage.region,
      model: usage.model,
      account: account.label,
      turnId: usage.turnId,
      at: Date.now(),
      ok,
      ...(tracker.ttftMs === undefined ? {} : { ttftMs: tracker.ttftMs }),
      ...(tracker.decodeMs === undefined ? {} : { decodeMs: tracker.decodeMs }),
      ...(tracker.usage === undefined ? {} : { usage: tracker.usage }),
    })
  }
  let sawDone = false
  // Forwarded BYTE FOR BYTE: a frame is sliced by offset and the original buffer
  // is pushed, never decoded and re-encoded. Decoding here would risk a U+FFFD at
  // a split boundary, and one replacement character in the middle of an answer is
  // a bug the user reads but the logs cannot explain.
  let pending = Buffer.alloc(0)
  const strip = new Transform({
    transform(this: Transform, chunk: Buffer, _encoding: BufferEncoding, done: (error?: Error | null) => void): void {
      // Idempotent: the tracker keeps the earliest byte, so calling it per chunk
      // costs nothing beyond one Date.now() and cannot skew the measurement.
      tracker.markFirstByte(Date.now())
      pending = pending.length === 0 ? Buffer.from(chunk) : Buffer.concat([pending, chunk])
      const keep: Buffer[] = []
      for (;;) {
        const span = frameSpan(pending)
        if (span === undefined) break
        const frame = pending.subarray(0, span.contentEnd).toString('utf8')
        const seen = inspectSseFrame(frame)
        if (seen === undefined) {
          keep.push(pending.subarray(0, span.frameEnd))
        } else {
          // Feed usage from EVERY frame that carries it, not only from the
          // trailer: a gateway that reports usage on its last content chunk
          // instead of a separate trailer frame would otherwise look like it
          // reported nothing at all. Observing never decides deletion - only
          // `usageOnly` does, and a content frame is never dropped.
          tracker.observe(seen.parsed)
          if (!seen.usageOnly) keep.push(pending.subarray(0, span.frameEnd))
        }
        pending = pending.subarray(span.frameEnd)
      }
      if (keep.length === 0) return done()
      this.push(keep.length === 1 ? keep[0] : Buffer.concat(keep))
      done()
    },
    flush(done: (error?: Error | null) => void): void {
      // A trailing fragment with no blank line is still the user's text, and the
      // host reads end-of-stream as the end of the answer. Dropping it would
      // silently truncate the last words of every reply.
      if (pending.length > 0) this.push(pending)
      tracker.finish(Date.now())
      finish(sawDone)
      done()
    },
  })
  const body = Readable.fromWeb(result.response.body as Parameters<typeof Readable.fromWeb>[0])
  body.on('data', (chunk: Buffer) => {
    if (chunk.includes('[DONE]')) sawDone = true
  })
  body.on('error', (error: unknown) => {
    logger?.warn('dsh-xdpool: upstream stream failed mid-flight', error)
    finish(false)
    if (!sawDone && res.writable) res.end('data: [DONE]\n\n')
  })
  body.pipe(strip).pipe(res)
}
export interface RecoverOptions {
  raw: string
  modelId: string | undefined
  controller: AbortController
  region: WorkBuddyRegion | undefined
  logger: ShimLogger | undefined
  client: WorkBuddyUpstreamClient
  pool: WorkBuddyAccountPool
  maxAttempts: number
  /** True context window for the model, so the budget fits the real limit. */
  contextWindow?: number
  /**
   * Where this retry's calls are filed.
   *
   * Carried in rather than minted here so the compaction retry shares the
   * original turn's identity: compacting and sending again is another PHYSICAL
   * call for the SAME user request.
   */
  usage?: UsageContext
}
export type RecoverResult =
  | { ok: true; account: WorkBuddyAccount; result: Extract<ChatStreamResult, { ok: true }> }
  | { ok: false; detail: string }
/**
 * Compact an over-long conversation and retry it once.
 *
 * Strategy, in order:
 *  1. drop the oldest turns, keeping system messages and the newest exchange;
 *  2. ask the model to summarise the dropped turns and splice that summary in;
 *  3. hard-truncate as a last resort.
 *
 * Returns `ok: false` only when even a truncated prompt still overran — the
 * caller then surfaces the original actionable 400.
 */
async function recoverFromContextOverrun(options: RecoverOptions): Promise<RecoverResult> {
  const { raw, modelId, controller, region, logger, client, pool, maxAttempts, usage } = options
  const parsed = client.parseChatBody(raw)
  if (parsed === undefined) return { ok: false, detail: 'request body was not parseable JSON' }
  const rawMessages = parsed['messages']
  if (!Array.isArray(rawMessages)) return { ok: false, detail: 'request carried no messages array' }
  const messages = rawMessages.filter(
    (value): value is ChatMessage => typeof value === 'object' && value !== null && !Array.isArray(value),
  )
  if (messages.length === 0) return { ok: false, detail: 'request carried no usable messages' }
  // The upstream reports the overrun but not the window size, so the budget has
  // to be derived from evidence rather than from the catalog alone.
  const overrunTokens = estimateMessagesTokens(messages)
  // Use the model's REAL context window when known (from the catalog); only
  // fall back to half the prompt when it is unknown.
  //
  // …but NEVER trust it as an upper bound, which is the bug this fixes: the
  // catalog advertises `deepseek-v4.1-flash` at 1M, so the budget computed to
  // 0.8 * 1M - 2048 = 797952 while the rejected prompt was already 791793
  // tokens. Compacting "to" a target LARGER than the prompt changed nothing, the
  // retry overran again, and the log line looked like the recovery had run.
  //
  // The prompt in hand just overran, so it is a hard, EVIDENCE-BASED ceiling:
  // whatever the catalog claims, the budget must sit meaningfully below it.
  const realWindow = options.contextWindow
  const fromWindow = realWindow !== undefined && realWindow > 0
    ? Math.max(512, Math.floor(realWindow * 0.8) - 2048)
    : Number.POSITIVE_INFINITY
  // Half the failing prompt: its size is known to be too big, so halving it both
  // guarantees real shrinkage and leaves headroom for the answer.
  const fromOverrun = Math.max(512, Math.floor(overrunTokens / 2))
  const budget = Math.min(fromWindow, fromOverrun)
  logger?.warn(
    `dsh-xdpool: context overrun on ${modelId ?? '(no model)'} `
      + `(~${overrunTokens} tokens, catalog window ${realWindow ?? 'unknown'}); `
      + `compacting to ~${budget} and retrying once`,
  )
  let summary: string | undefined
  let compacted: ChatMessage[] = messages
  let compactionDetail = ''
  try {
    const summariser = await pool.acquire(modelId, region)
    if (summariser === undefined) {
      compactionDetail = 'no account available to summarise with'
    } else {
      const outcome = await compactWithSummary(
        messages,
        { budget, keepRecent: 6 },
        {
          complete: async (request, signal) => {
            const body = client.buildChatBody(
              { ...parsed, stream: true, max_tokens: Math.max(256, Math.floor(budget / 2)) },
              request,
            )
            return await client.completeChat(summariser.credential, body, signal ?? controller.signal)
          },
        },
        controller.signal,
      )
      compacted = outcome.messages
      summary = outcome.summary
      if (outcome.skipped !== undefined) compactionDetail = outcome.skipped
    }
  } catch (error: unknown) {
    // Summarisation is best-effort; fall through to truncation.
    compactionDetail = `summarisation failed: ${String(error)}`
  }
  // Whatever the summariser managed, make sure the prompt now fits.
  if (estimateMessagesTokens(compacted) > budget) {
    compacted = hardTruncate(compacted, budget).messages
  }
  if (summary === undefined && estimateMessagesTokens(compacted) >= overrunTokens) {
    return { ok: false, detail: compactionDetail === '' ? 'compaction could not reduce the prompt' : compactionDetail }
  }
  const retryBody = client.buildChatBody(parsed, compacted)
  const tried: string[] = []
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (controller.signal.aborted) return { ok: false, detail: 'client disconnected' }
    const account = await pool.acquire(modelId, region)
    if (account === undefined) return { ok: false, detail: 'no account available after compaction' }
    tried.push(account.label)
    const result = await client.chatStream(
      account.credential,
      retryBody,
      controller.signal,
      upstreamConversationId(conversationKeyOf(retryBody)),
    )
    if (!result.ok) {
      // A refusal is filed like any other failed physical call. The success
      // below deliberately is NOT: that one is filed by the forwarder when the
      // stream ends, so filing it here too would count the same call twice.
      usage?.recorder.record({
        region: usage.region,
        model: usage.model,
        account: account.label,
        turnId: usage.turnId,
        at: Date.now(),
        ok: false,
      })
    }
    if (result.ok) {
      logger?.info?.(
        `dsh-xdpool: recovered from context overrun on ${modelId ?? '(no model)'} `
          + `(summarised: ${summary === undefined ? 'no' : 'yes'})`,
      )
      return { ok: true, account, result }
    }
    if (isContextTooLong(result.message)) {
      // Still too long even after compaction: give up rather than loop.
      return { ok: false, detail: 'prompt still exceeded the window after compaction' }
    }
    if (result.kind === 'session_dead') {
      // Same rule as the main loop: try a refresh, and if the credential is
      // proven dead cool it so this retry budget is not spent on it again.
      const before = account.credential.accessToken
      const recovered = await pool.refreshAccount(account.id, { force: true })
      if (!recovered || account.credential.accessToken === before) pool.penalizeCredentialDead(account.id)
      continue
    }
    if (result.kind === 'hard_credit') {
      pool.penalizeExhausted(account.id)
      continue
    }
    if (result.kind === 'soft_rate') {
      pool.penalize(account.id, parseRateLimitReset(result.message), modelId)
      continue
    }
    return { ok: false, detail: `upstream ${result.kind} after compaction` }
  }
  return { ok: false, detail: `no account served the compacted request (tried ${tried.length})` }
}
