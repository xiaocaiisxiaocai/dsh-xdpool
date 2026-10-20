/**
 * 免密车道的出口代理（CONNECT 隧道）。
 *
 * 这条功能的全部意义是「让免费车道换一个出口」，所以测的重点不是解析 URL，而是
 * 三件会真正决定出口的事：
 *
 *  1. 配了代理就一定走隧道（`freeFetch` 必须先 CONNECT 再发请求）；
 *  2. 隧道失败要**报错**，绝不静默回落直连 —— 回落等于把用户要求藏起来的地址
 *     重新暴露出去；
 *  3. 配置坏掉 = 直连，且不许让池子起不来。
 *
 * 测试用进程内的假 CONNECT 代理，不碰外网。
 */
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { freeFetch, freeLane } from '../src/free-upstream.ts'
import { freeProxy, freeProxyPath, freeProxyUrl, openTunnel, parseProxyUrl } from '../src/free-proxy.ts'

/** 一个只记录 CONNECT 目标的假代理；`answer` 决定它怎么回。 */
function fakeProxy(answer: (target: string) => string): Promise<{
  url: string
  seen: string[]
  close: () => Promise<void>
}> {
  const seen: string[] = []
  const server = http.createServer((_req, res) => {
    res.writeHead(405)
    res.end()
  })
  server.on('connect', (req, socket) => {
    const target = req.url ?? ''
    seen.push(target)
    socket.write(answer(target))
    socket.end()
  })
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port
      resolve({
        url: `http://127.0.0.1:${port}`,
        seen,
        close: () => new Promise<void>(done => server.close(() => done())),
      })
    })
  })
}

const OK = 'HTTP/1.1 200 Connection Established\r\n\r\n'

describe('代理 URL 的解析与读取', () => {
  const saved = { env: process.env.XDPOOL_FREE_PROXY }

  afterEach(() => {
    if (saved.env === undefined) delete process.env.XDPOOL_FREE_PROXY
    else process.env.XDPOOL_FREE_PROXY = saved.env
  })

  it('接受 http / https，缺省端口按协议补', () => {
    expect(parseProxyUrl('http://127.0.0.1:7890')?.port).toBe(7890)
    expect(parseProxyUrl('https://proxy.example')?.port).toBe(443)
    expect(parseProxyUrl('http://proxy.example')?.port).toBe(80)
  })

  it('省协议的写法按 http 处理', () => {
    const parsed = parseProxyUrl('127.0.0.1:7890')
    expect(parsed?.protocol).toBe('http:')
    expect(parsed?.host).toBe('127.0.0.1')
    expect(parsed?.port).toBe(7890)
  })

  it('带凭据时生成 Proxy-Authorization', () => {
    const parsed = parseProxyUrl('http://user:p%40ss@127.0.0.1:7890')
    expect(parsed?.authorization).toBe(`Basic ${Buffer.from('user:p@ss').toString('base64')}`)
  })

  it('socks、畸形值、空值都是「直连」，不抛异常', () => {
    expect(parseProxyUrl('socks5://127.0.0.1:7891')).toBeUndefined()
    expect(parseProxyUrl('http://')).toBeUndefined()
    expect(parseProxyUrl('http://127.0.0.1:99999')).toBeUndefined()
    expect(parseProxyUrl('   ')).toBeUndefined()
  })

  it('环境变量优先于文件，且文件读不到等于直连', () => {
    process.env.XDPOOL_FREE_PROXY = 'http://127.0.0.1:1111'
    expect(freeProxyUrl()).toBe('http://127.0.0.1:1111')
    expect(freeProxy()?.port).toBe(1111)
    delete process.env.XDPOOL_FREE_PROXY
    // 指到一个必然不存在的文件：读失败 → 直连。
    expect(freeProxy({ DSH_HOME: 'Z:\\definitely-missing-dsh-home' })).toBeUndefined()
    expect(freeProxyPath({ DSH_HOME: 'C:\\dsh' })).toBe('C:\\dsh\\.xdpool\\free-proxy')
  })
})

describe('CONNECT 隧道', () => {
  it('握手成功后把目标主机端口写在 CONNECT 请求行里', async () => {
    const proxy = await fakeProxy(() => OK)
    try {
      const tunnel = await openTunnel(parseProxyUrl(proxy.url)!, 'opencode.ai', 443, { timeoutMs: 5000 })
      expect(proxy.seen).toEqual(['opencode.ai:443'])
      tunnel.destroy()
    } finally {
      await proxy.close()
    }
  })

  it('非 2xx 直接 reject，不把半个通道交出去', async () => {
    const proxy = await fakeProxy(() => 'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
    try {
      let message = ''
      try {
        await openTunnel(parseProxyUrl(proxy.url)!, 'opencode.ai', 443, { timeoutMs: 5000 })
      } catch (error) {
        message = (error as Error).message
      }
      expect(message).toContain('407')
    } finally {
      await proxy.close()
    }
  })
})

describe('freeFetch 的出口选择', () => {
  const saved = { env: process.env.XDPOOL_FREE_PROXY }
  afterEach(() => {
    if (saved.env === undefined) delete process.env.XDPOOL_FREE_PROXY
    else process.env.XDPOOL_FREE_PROXY = saved.env
    freeLane.fetch = null
  })

  it('配了代理时，HTTPS 请求先经 CONNECT 到目标主机', async () => {
    const proxy = await fakeProxy(() => OK)
    process.env.XDPOOL_FREE_PROXY = proxy.url
    try {
      // 隧道通了但 TLS 对端不存在（假代理立刻断开），请求必然失败；
      // 这里只关心「它确实先 CONNECT 了目标」——出口已经被换掉的证据。
      await freeFetch('https://free-lane.invalid/v1/models').catch(() => undefined)
      expect(proxy.seen).toEqual(['free-lane.invalid:443'])
    } finally {
      await proxy.close()
    }
  })

  it('没配代理时不经过任何代理（保持原直连路径）', async () => {
    const proxy = await fakeProxy(() => OK)
    delete process.env.XDPOOL_FREE_PROXY
    try {
      await freeFetch('https://free-lane.invalid/v1/models', { signal: AbortSignal.timeout(1500) }).catch(
        () => undefined,
      )
      expect(proxy.seen).toEqual([])
    } finally {
      await proxy.close()
    }
  })

  it('测试接缝优先于代理配置（用例不该因为本机配了代理就出网）', async () => {
    process.env.XDPOOL_FREE_PROXY = 'http://127.0.0.1:1'
    let called = 0
    freeLane.fetch = {
      fetch: async () => {
        called += 1
        return new Response('{}', { status: 200 })
      },
    }
    const response = await freeFetch('https://free-lane.invalid/v1/models')
    expect(called).toBe(1)
    expect(response.status).toBe(200)
  })
})
