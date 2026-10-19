/**
 * The client-identity headers on chat completions, and the conversation
 * identifiers the gateway refuses to work without.
 *
 * The identity headers exist for one reason: the gateway attributes every
 * `/v2/chat/completions` to a client, and that attribution is what the user
 * sees in their billing console as the "使用端" column. The desktop app sends
 * `X-IDE-Type`/`X-IDE-Name`/`X-IDE-Version` and reads as "WorkBuddy"; without
 * them our requests attributed to nothing and the column showed "–" — which
 * read as broken billing even though every credit was deducted correctly.
 *
 * The conversation identifiers exist for a blunter reason: without all three of
 * `X-Conversation-ID`, `X-Conversation-Request-ID` and
 * `X-Conversation-Message-ID`, the gateway answers HTTP 400 / code 11128
 * ("request illegal", displayTips about failing channel verification) and the
 * turn never runs at all. That was a total outage of the WorkBuddy lane, not a
 * cosmetic one.
 *
 * The regression these guard against is subtle, which is why the assertions are
 * on the exact header set rather than "some headers exist": the temptation when
 * refactoring is to fold the identity headers into the shared `chatHeaders()`,
 * which would put them on the points-automation endpoints too — endpoints the
 * desktop app has never been shown to send them on. Both directions are wrong,
 * so both are pinned.
 */
import { describe, expect, it } from 'vitest'
import { WorkBuddyUpstreamClient, type WorkBuddyCredential } from '../src/upstream.ts'

/** A minimal credential; the headers under test do not depend on its details. */
function credential(): WorkBuddyCredential {
  return {
    accessToken: 'tok',
    refreshToken: 'ref',
    uid: 'u1',
    enterpriseId: 'e1',
    domain: 'd1',
  } as unknown as WorkBuddyCredential
}

/** A recording fetch that answers a chat with SSE and anything else with JSON. */
function recordingFetch() {
  const seen: { url: string; headers: Record<string, string> }[] = []
  const impl = async (url: unknown, init: RequestInit): Promise<Response> => {
    const target = String(url)
    seen.push({ url: target, headers: init.headers as Record<string, string> })
    // Chat completions stream; every other endpoint answers a JSON envelope.
    const isChat = target.includes('/v2/chat/completions')
    return new Response(isChat ? 'data: [DONE]\n\n' : '{"code":0,"data":[]}\n', {
      status: 200,
      headers: { 'Content-Type': isChat ? 'text/event-stream' : 'application/json' },
    })
  }
  return { seen, options: { fetchImpl: impl as unknown as typeof fetch } }
}

/** Every path in the client that POSTs a chat completion. */
function chatPaths(): { name: string; run: (client: WorkBuddyUpstreamClient) => Promise<unknown> }[] {
  return [
    { name: 'completeChat', run: (c) => c.completeChat(credential(), '{}') },
    { name: 'chatStream', run: (c) => c.chatStream(credential(), '{}') },
  ]
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

describe('chat completions carry the desktop client identity', () => {
  for (const path of chatPaths()) {
    it(`${path.name} sends the three X-IDE headers`, async () => {
      const { seen, options } = recordingFetch()
      const client = new WorkBuddyUpstreamClient(options)
      await path.run(client)
      expect(seen).toHaveLength(1)
      expect(seen[0].url).toContain('/v2/chat/completions')
      expect(seen[0].headers['X-IDE-Type']).toBe('WorkBuddy')
      expect(seen[0].headers['X-IDE-Name']).toBe('WorkBuddy')
      expect(seen[0].headers['X-IDE-Version']).toBe('5.5.6')
    })

    it(`${path.name} keeps the shared auth and product headers alongside them`, async () => {
      const { seen, options } = recordingFetch()
      const client = new WorkBuddyUpstreamClient(options)
      await path.run(client)
      // The identity headers must not have REPLACED the auth contract.
      expect(seen[0].headers['Authorization']).toBe('Bearer tok')
      expect(seen[0].headers['X-Product']).toBe('SaaS')
      expect(seen[0].headers['X-User-Id']).toBe('u1')
    })

    it(`${path.name} sends all three conversation identifiers`, async () => {
      const { seen, options } = recordingFetch()
      const client = new WorkBuddyUpstreamClient(options)
      await path.run(client)
      // All three are mandatory: dropping any ONE of them is HTTP 400 / 11128.
      expect(seen[0].headers['X-Conversation-ID']).toMatch(UUID)
      expect(seen[0].headers['X-Conversation-Request-ID']).toMatch(UUID)
      expect(seen[0].headers['X-Conversation-Message-ID']).toMatch(UUID)
    })
  }

  it('chatStream reuses a caller-supplied conversation id but mints fresh request ids', async () => {
    const { seen, options } = recordingFetch()
    const client = new WorkBuddyUpstreamClient(options)
    const conversationId = '11111111-2222-3333-4444-555555555555'
    await client.chatStream(credential(), '{}', undefined, conversationId)
    await client.chatStream(credential(), '{}', undefined, conversationId)
    // Same thread upstream...
    expect(seen[0].headers['X-Conversation-ID']).toBe(conversationId)
    expect(seen[1].headers['X-Conversation-ID']).toBe(conversationId)
    // ...but each request is its own request/message.
    expect(seen[0].headers['X-Conversation-Request-ID'])
      .not.toBe(seen[1].headers['X-Conversation-Request-ID'])
    expect(seen[0].headers['X-Conversation-Message-ID'])
      .not.toBe(seen[1].headers['X-Conversation-Message-ID'])
  })
})

describe('non-chat endpoints stay free of identity headers', () => {
  it('the points-automation task list does not claim to be the desktop app', async () => {
    const { seen, options } = recordingFetch()
    const client = new WorkBuddyUpstreamClient(options)
    await client.listTasks(credential())
    expect(seen).toHaveLength(1)
    expect(seen[0].url).not.toContain('/v2/chat/completions')
    expect(seen[0].headers['X-IDE-Type']).toBeUndefined()
    expect(seen[0].headers['X-IDE-Name']).toBeUndefined()
    expect(seen[0].headers['X-Conversation-ID']).toBeUndefined()
  })

  it('openConversation keeps sending its own identity headers', async () => {
    // The automation's conversation opener predates this fix and already sent
    // the three headers inline. It now shares the same constant, so pinning it
    // here catches one path drifting from the other.
    const { seen, options } = recordingFetch()
    const client = new WorkBuddyUpstreamClient(options)
    const opened = await client.openConversation(credential())
    // openConversation tolerates a stream that ends immediately.
    expect(seen).toHaveLength(1)
    expect(seen[0].headers['X-IDE-Type']).toBe('WorkBuddy')
    expect(opened === undefined || typeof opened === 'object').toBe(true)
  })
})

describe('prepareChatBody guarantees the gateway contract', () => {
  const client = new WorkBuddyUpstreamClient(recordingFetch().options)
  const parse = (raw: string): Record<string, unknown> =>
    JSON.parse(client.prepareChatBody(raw)) as Record<string, unknown>

  function roles(raw: string): unknown[] {
    return (parse(raw)['messages'] as Record<string, unknown>[]).map((m) => m['role'])
  }

  it('hoists a later system message to the front instead of dropping it', () => {
    const raw = JSON.stringify({
      model: 'm',
      messages: [
        { role: 'user', content: 'hi' },
        { role: 'system', content: 'sys' },
      ],
    })
    expect(roles(raw)).toEqual(['system', 'user'])
    // The caller's text is preserved, not replaced.
    expect((parse(raw)['messages'] as Record<string, unknown>[])[0]['content']).toBe('sys')
  })

  it('synthesises an empty system message when the caller sent none', () => {
    // The gateway only checks the role of messages[0], so an empty system turn
    // is enough — and inventing prompt text would change what the model sees.
    const raw = JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'hi' }] })
    expect(roles(raw)).toEqual(['system', 'user'])
    expect((parse(raw)['messages'] as Record<string, unknown>[])[0]['content']).toBe('')
  })

  it('treats a relabelled developer turn as the system message it became', () => {
    // `developer` is rewritten to `system` first; if that rewrite left the turn
    // in place, a developer-first request would still trip 11128.
    const raw = JSON.stringify({ model: 'm', messages: [{ role: 'developer', content: 'sys' }] })
    expect(roles(raw)).toEqual(['system'])
  })

  it('leaves an already-conforming body alone', () => {
    const raw = JSON.stringify({
      model: 'm',
      messages: [
        { role: 'system', content: 'sys' },
        { role: 'user', content: 'hi' },
      ],
    })
    expect(roles(raw)).toEqual(['system', 'user'])
    expect(parse(raw)['stream']).toBe(true)
  })
})
