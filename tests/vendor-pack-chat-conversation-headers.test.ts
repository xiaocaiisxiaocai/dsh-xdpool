/**
 * vendored 渠道包里 WorkBuddy / CodeBuddy 聊天的三条会话标识头。
 *
 * 上游网关对 `/v2/chat/completions` 的检查是「客户端身份 + 会话身份」两段：
 * 身份头（`X-IDE-*`）决定用量归到哪个「使用端」，会话头决定这次调用
 * 是不是一条真实线程的延续。第二段缺任何一条都是 HTTP 400 + 业务码 11128，
 * `msg: "request illegal"`，附一段「没通过渠道校验、可能不是官方客户端发出的」
 * 的 displayTips —— 提示语与真因无关，所以这条回归很容易被误判成 UA/产品头问题。
 *
 * 这里钉三件事，因为每一件都曾在仓库里被改坏过：
 *
 *  1. 三条头都必须出现在 `BuddyAdapter.send()` 里。它是唯一的 chat 出口，
 *     首轮与换号重试都走它；补在别处（比如 `buildBody` 或 RPC 层）会漏掉重试。
 *  2. 会话 id 必须由首条 user 消息**确定性**派生：同一会话多轮稳定、跨进程稳定。
 *     改成每次 `randomUUID()` 也能过门禁，但每个回合在上游都是一条新线程，
 *     线程视图碎掉、连续会话的计价也拿不到。
 *  3. 请求 id / 消息 id 必须每次都新造：重发不能被上游当成同一条请求去重。
 *
 * 断言分两层：静态层读 `pack.js` 源码（vendored 包不能安全 import —— 它依赖宿主
 * 版本的 `@deepseek-ai/schemastery`，独立进程里 `.volatile()` 就不存在），
 * 行为层把真正随包发布的三个函数切出来在沙箱里跑，验证稳定性与唯一性。
 */
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'

const PACK = new URL('../vendor/channel-pack/pack.js', import.meta.url)
const source = readFileSync(PACK, 'utf8')

/** `send()` 的源码窗口：从这里之后到下一个方法之前。 */
function sendBody(): string {
  const start = source.indexOf('async send(credential, body, options) {')
  expect(start).toBeGreaterThan(-1)
  const end = source.indexOf('async *consumeSse(', start)
  expect(end).toBeGreaterThan(start)
  return source.slice(start, end)
}

/** 把随包发布的三个会话头函数切出来，在沙箱里执行，拿到它们的真实行为。 */
function loadConversationHelpers(): {
  conversationScopedId: (body: string, sessionId?: string) => string
  chatConversationHeaders: (body: string, sessionId?: string) => {
    conversationId: string
    requestId: string
    messageId: string
  }
  firstUserMessageSeed: (body: string) => string | undefined
} {
  const start = source.indexOf('function firstUserMessageSeed(')
  const end = source.indexOf('var BuddyAdapter = class')
  expect(start).toBeGreaterThan(-1)
  expect(end).toBeGreaterThan(start)
  const block = source.slice(start, end)
  const factory = new Function(
    '__ofmConversationHash',
    'crypto',
    `${block}
     return { firstUserMessageSeed, conversationScopedId, chatConversationHeaders }`,
  ) as (
    hash: typeof createHash,
    webcrypto: Crypto,
  ) => {
    conversationScopedId: (body: string, sessionId?: string) => string
    chatConversationHeaders: (body: string, sessionId?: string) => {
      conversationId: string
      requestId: string
      messageId: string
    }
    firstUserMessageSeed: (body: string) => string | undefined
  }
  return factory(createHash, globalThis.crypto)
}

/** 一段最小聊天请求体，模拟 DSH 一回合的形态。 */
function chatBody(userText: string, turns = 2): string {
  const messages: { role: string; content: string }[] = [{ role: 'system', content: 'sys' }]
  for (let i = 0; i < turns; i += 1) {
    messages.push({ role: 'user', content: i === 0 ? userText : `${userText} #${i}` })
    messages.push({ role: 'assistant', content: 'ok' })
  }
  return JSON.stringify({ model: 'deepseek-v4.1-flash', stream: true, messages })
}

/** 会话 id / 请求 id 的形状：UUID v4，变体位按 RFC 4122 取 8/9/a/b。 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

describe('vendored 渠道包的聊天请求带上三条会话标识头', () => {
  it('三条头都设在 send() 里，且全仓库只出现这一次', () => {
    const body = sendBody()
    for (const name of [
      'X-Conversation-ID',
      'X-Conversation-Request-ID',
      'X-Conversation-Message-ID',
    ]) {
      expect(body).toContain(`headers.set("${name}"`)
      // 只有一处：cat 到非聊天端点上就会把签到/报表的流量也改了形状。
      expect(source.split(`"${name}"`).length - 1).toBe(1)
    }
  })

  it('补头窗口覆盖 chat 出口，非聊天端点不带这些头', () => {
    // `/v2/chat/completions` 在 send() 里拼出来，三条头就设在同一个 Headers 上。
    expect(sendBody()).toContain('/v2/chat/completions')
    // 全包各自的 fetch 调用点（签到 / 报表 / 积分 / 免密车道）都不得带会话头：
    // 三条头在整个文件里只出现一次，已在上一用例钉住；这里确认它们不在别的
    // Headers 构造里——即全包只有 `new Headers(...)` 之后的 send() 这一处补丁。
    const headersCtors = source.split('new Headers(').length - 1
    expect(headersCtors).toBeGreaterThan(1)
    expect(sendBody()).toContain('new Headers(attributionHeaders2())')
  })
})

describe('会话 id 的稳定性与请求 id 的唯一性', () => {
  it('同一会话的后续回合复用同一个会话 id', () => {
    const { conversationScopedId } = loadConversationHelpers()
    const first = conversationScopedId(chatBody('第一句话', 1))
    const later = conversationScopedId(chatBody('第一句话', 4))
    expect(later).toBe(first)
  })

  it('不同会话得到不同会话 id', () => {
    const { conversationScopedId } = loadConversationHelpers()
    expect(conversationScopedId(chatBody('会话 A'))).not.toBe(conversationScopedId(chatBody('会话 B')))
  })

  it('会话 id 是 UUID 形状，且不随进程状态漂移', () => {
    const { conversationScopedId } = loadConversationHelpers()
    const id = conversationScopedId(chatBody('形状'))
    expect(id).toMatch(UUID)
    // 同一个种子再算一次必须一模一样：跨重启、跨账号重发都要落回同一条线程。
    expect(conversationScopedId(chatBody('形状'))).toBe(id)
  })

  it('每次请求的 request / message id 都是新的', () => {
    const { chatConversationHeaders } = loadConversationHelpers()
    const body = chatBody('唯一性')
    const a = chatConversationHeaders(body, 'sess')
    const b = chatConversationHeaders(body, 'sess')
    expect(a.conversationId).toBe(b.conversationId)
    expect(a.requestId).not.toBe(b.requestId)
    expect(a.messageId).not.toBe(b.messageId)
    expect(a.requestId).toMatch(UUID)
    expect(a.messageId).toMatch(UUID)
  })

  it('没有 user 消息时退回 sessionId，仍然给出可用的 UUID', () => {
    const { conversationScopedId, chatConversationHeaders } = loadConversationHelpers()
    const body = JSON.stringify({ messages: [{ role: 'system', content: 'only sys' }] })
    expect(conversationScopedId(body, 'session-abc')).toMatch(UUID)
    expect(chatConversationHeaders(body, 'session-abc').conversationId).toBe(
      conversationScopedId(body, 'session-abc'),
    )
  })

  it('坏 JSON 不抛异常（失败照常发请求，交给上游判）', () => {
    const { conversationScopedId, firstUserMessageSeed } = loadConversationHelpers()
    expect(firstUserMessageSeed('{not json')).toBeUndefined()
    expect(conversationScopedId('{not json', 'sess')).toMatch(UUID)
  })
})
