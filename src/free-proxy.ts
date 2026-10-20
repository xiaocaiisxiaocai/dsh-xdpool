/**
 * 免密车道的出口代理。
 *
 * WHY THIS EXISTS
 *
 * `freeFetch()` 故意用 `node:http`/`node:https` 直连（见 `free-upstream.ts`：
 * 本地代理插件靠替换 `globalThis.fetch` 工作，而替换会重排请求体）。代价是这条车道
 * 永远从本机地址出去 —— 上游一旦按 IP 判决（OpenCode 免费池就报 `free_client`：
 * “abusive traffic from this IP”），宿主侧没有任何开关能把这一条车道换个出口。
 *
 * 这里补的就是那个开关：给免密车道一个 HTTP CONNECT 隧道出口。只作用于本车道的
 * HTTPS 请求，不动全局 `fetch`、不动其它车道。
 *
 * 配置（两处，环境变量优先）：
 *
 *   1. `XDPOOL_FREE_PROXY=http://user:pass@127.0.0.1:7890`
 *   2. `<DSH_HOME>/.xdpool/free-proxy` 里一行同样的 URL（`#` 开头为注释）
 *
 * 值为空/解析不出来 = 直连，且绝不因为配置坏掉而让池子起不来 —— 与
 * `proxy-store.ts` 的读取策略一致。链上失败时**不回落直连**：静默回落会把真实
 * 出口暴露出去，正是这个功能要避免的事。
 *
 * @module src/free-proxy
 */
import { readFileSync } from 'node:fs'
import { connect as netConnect, type Socket } from 'node:net'
import { join } from 'node:path'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { pluginDataDir } from './ignored.ts'

/** 环境变量名。优先级高于文件。 */
export const FREE_PROXY_ENV = 'XDPOOL_FREE_PROXY'

/** 允许的代理 URL 形状（都走 CONNECT；SOCKS 不在本模块范围内）。 */
export interface FreeProxy {
  protocol: 'http:' | 'https:'
  host: string
  port: number
  /** 已编码的 `Proxy-Authorization` 值；没有凭据时缺省。 */
  authorization?: string
}

/** `<DSH_HOME>/.xdpool/free-proxy` —— 免密车道出口的单行配置。 */
export function freeProxyPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(pluginDataDir(env), 'free-proxy')
}

/**
 * 解析一行代理 URL。
 *
 * 宽容但不说谎：给了 `socks5://`、端口越界、畸形 URL 一律返回 `undefined`
 * （= 直连），而不是抛异常或猜一个协议。
 */
export function parseProxyUrl(raw: string | undefined): FreeProxy | undefined {
  const trimmed = (raw ?? '').trim()
  if (trimmed === '') return undefined
  let url: URL
  try {
    // `127.0.0.1:7890` 这种省协议的写法按 http 处理，和 curl 的习惯一致。
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`)
  } catch {
    return undefined
  }
  const protocol = url.protocol.toLowerCase()
  if (protocol !== 'http:' && protocol !== 'https:') return undefined
  const host = url.hostname.trim()
  if (host === '') return undefined
  const port = url.port === '' ? (protocol === 'https:' ? 443 : 80) : Number(url.port)
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) return undefined
  const authorization =
    url.username === '' && url.password === ''
      ? undefined
      : `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}`
  return {
    protocol: protocol as FreeProxy['protocol'],
    host,
    port,
    ...(authorization === undefined ? {} : { authorization }),
  }
}

/** 文件里的第一条有效行；读不到或全是注释时 `undefined`。 */
export function readFreeProxyFile(path: string = freeProxyPath()): string | undefined {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    return undefined
  }
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    return trimmed
  }
  return undefined
}

/** 生效的代理 URL：环境变量 → 文件。 */
export function freeProxyUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const fromEnv = (env[FREE_PROXY_ENV] ?? '').trim()
  if (fromEnv !== '') return fromEnv
  return readFreeProxyFile(freeProxyPath(env))
}

/** 生效的代理；未配置或配置无效时 `undefined`（= 直连）。 */
export function freeProxy(env: NodeJS.ProcessEnv = process.env): FreeProxy | undefined {
  return parseProxyUrl(freeProxyUrl(env))
}

/**
 * 打开到 `targetHost:targetPort` 的 CONNECT 隧道。
 *
 * 只做握手与状态码判定：2xx 交回已连通的 socket（隧道内还是明文 TCP，
 * HTTPS 由 `tlsOverTunnel()` 在其上再握手），其余一律 reject 并销毁 socket，
 * 避免把半个通道交出去。
 */
export function openTunnel(
  proxy: FreeProxy,
  targetHost: string,
  targetPort: number,
  options: { timeoutMs?: number; signal?: AbortSignal | undefined } = {},
): Promise<Socket> {
  const timeoutMs = options.timeoutMs ?? 15_000
  return new Promise<Socket>((resolve, reject) => {
    const socket = netConnect({ host: proxy.host, port: proxy.port })
    let settled = false
    const finish = (error?: Error): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.removeListener('data', onData)
      if (error !== undefined) {
        socket.destroy()
        reject(error)
        return
      }
      resolve(socket)
    }
    const timer = setTimeout(
      () => finish(new Error(`free proxy ${proxy.host}:${proxy.port} CONNECT timed out after ${timeoutMs}ms`)),
      timeoutMs,
    )
    let buffered = ''
    const onData = (chunk: Buffer): void => {
      buffered += chunk.toString('latin1')
      const end = buffered.indexOf('\r\n\r\n')
      if (end < 0) return
      const statusLine = buffered.slice(0, buffered.indexOf('\r\n')).trim()
      const status = Number(statusLine.split(/\s+/)[1] ?? 0)
      if (!(status >= 200 && status < 300)) {
        finish(new Error(`free proxy ${proxy.host}:${proxy.port} CONNECT answered ${statusLine || '(empty)'}`))
        return
      }
      // CONNECT 响应之后不应再有多余字节；真有就原样推回流里，别吞掉。
      const rest = buffered.slice(end + 4)
      if (rest !== '') socket.unshift(Buffer.from(rest, 'latin1'))
      finish()
    }
    socket.setNoDelay(true)
    socket.once('error', (error: Error) =>
      finish(new Error(`free proxy ${proxy.host}:${proxy.port} ${error.message}`)),
    )
    socket.on('data', onData)
    socket.once('connect', () => {
      const lines = [`CONNECT ${targetHost}:${targetPort} HTTP/1.1`, `Host: ${targetHost}:${targetPort}`]
      if (proxy.authorization !== undefined) lines.push(`Proxy-Authorization: ${proxy.authorization}`)
      socket.write(`${lines.join('\r\n')}\r\n\r\n`, 'latin1')
    })
    options.signal?.addEventListener(
      'abort',
      () => finish(new Error('The operation was aborted')),
      { once: true },
    )
  })
}

/** 在隧道之上完成 TLS 握手，得到可以交给 `https.request()` 的 socket。 */
export function tlsOverTunnel(tunnel: Socket, servername: string): TLSSocket {
  return tlsConnect({ socket: tunnel, servername })
}
