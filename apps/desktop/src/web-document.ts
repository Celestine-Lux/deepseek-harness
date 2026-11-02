/** Local Web document and authenticated HTTP forwarding for the application window. */
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'

const MIME: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json',
  '.woff2': 'font/woff2', '.png': 'image/png', '.ico': 'image/x-icon',
}
const BOOT = '<script>globalThis.__DSH_BOOT_READY__ = Promise.withResolvers()</script>'

/**
 * Read an application-owned static asset; the index waits for asynchronous Host injections.
 * @param request - Local application request.
 * @param root - Packaged Web dist directory.
 * @returns Static response, or a missing/invalid path response.
 */
export async function serveWebDocument(request: Request, root: string): Promise<Response> {
  if (!['GET', 'HEAD'].includes(request.method)) return new Response(null, { status: 405 })
  const url = new URL(request.url)
  let pathname: string
  try { pathname = decodeURIComponent(url.pathname) } catch { return new Response(null, { status: 400 }) }
  const target = resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname))
  const directory = resolve(root)
  if (!target.startsWith(directory + sep)) return new Response(null, { status: 403 })
  let body: Buffer
  try { body = await readFile(target) } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new Response(null, { status: 404 })
    throw error
  }
  const content = pathname === '/' || pathname === '/index.html'
    ? body.toString().replace('<head>', '<head>' + BOOT) : new Uint8Array(body)
  return new Response(request.method === 'HEAD' ? null : content, {
    headers: { 'content-type': MIME[extname(target)] ?? 'application/octet-stream' },
  })
}

/**
 * Exchange the Host launch URL for an authority-bound browser cookie.
 * @param url - Authenticated URL reported by the owned Host process.
 * @returns Cookie header for requests forwarded to that Host.
 */
export async function authenticateWebHost(url: string): Promise<string> {
  const response = await fetch(url, { redirect: 'manual' })
  const cookie = response.headers.get('set-cookie')
  await response.body?.cancel()
  if (response.status !== 303 || cookie === null) throw new Error('Desktop Host authentication failed')
  const end = cookie.indexOf(';')
  return end < 0 ? cookie : cookie.slice(0, end)
}

/** Persistent storage of the browser-session cookies a Host hands to this shell. */
export interface HostCookieStore {
  /** @param filter - URL selecting the cookies of the Host authority. @returns every cookie stored for its host. */
  get(filter: { url: string }): Promise<readonly { name: string }[]>
  /** @param url - authenticated Host URL. @param name - cookie to delete. @returns after deletion. */
  remove(url: string, name: string): Promise<void>
}

/**
 * Delete the Host cookies earlier launches left in a persistent browser jar.
 * The Host picks a new port on every launch, and its cookie name, path, and
 * thirty-day lifetime are all derived from that authority, so each launch
 * stores one more cookie without replacing its predecessor. The accumulated
 * `Cookie` header eventually passes the Host's header limit, every launch is
 * refused with 431, and the window never opens again. This shell forwards the
 * current cookie itself, so nothing in the jar is needed after the exchange.
 * @param store - cookie store of the session that received the Host cookies.
 * @param url - authenticated Host URL of this launch.
 * @param cookie - `name=value` pair forwarded to that Host.
 * @returns names of the deleted cookies, in store order.
 * @throws When the pair carries no cookie name; deleting unguarded would empty the store.
 */
export async function forgetStaleHostCookies(
  store: HostCookieStore, url: string, cookie: string,
): Promise<string[]> {
  const at = cookie.indexOf('=')
  if (at <= 0) throw new Error('Desktop Host cookie has no name')
  const kept = cookie.slice(0, at)
  // Every cookie of this host belongs to a Host launch, because this shell owns
  // the authority and the page's own Cookie jar never sees these cookies.
  const stale = (await store.get({ url })).map(item => item.name).filter(name => name !== kept)
  for (const name of stale) await store.remove(url, name)
  return stale
}

/**
 * Response headers not relayed to the renderer. `set-cookie` would hand the
 * Host's authentication cookie to the page's cookie jar, which the shell owns
 * instead; the rest describe the Node `fetch` connection (its encoding, length,
 * and hop-by-hop transport), which Chromium never sees.
 */
const WITHHELD_RESPONSE_HEADERS = [
  'set-cookie',
  'content-encoding', 'content-length',
  'transfer-encoding', 'connection', 'keep-alive', 'te', 'trailer', 'upgrade', 'proxy-authenticate', 'proxy-authorization',
]

/** Host routes whose responses carry immutable cache headers keyed by a per-process revision. */
const PLUGIN_BUNDLE_PATH = /^\/plugins\//u

/**
 * Forward local application requests to its authenticated Host, preserving streaming and cancellation.
 * Plugin bundle responses lose their `cache-control` for `no-store`: the Host marks them immutable
 * under a revision that changes every launch, so Chromium's disk cache would only accumulate bundles
 * no later launch can reuse.
 * @param request - Request from the application origin.
 * @param host - Owned Host URL.
 * @param cookie - Host-issued authentication cookie.
 * @returns Host response without connection-level headers.
 */
export async function forwardWebRequest(request: Request, host: string, cookie: string): Promise<Response> {
  const source = new URL(request.url)
  const origin = request.headers.get('origin')
  if (origin !== null && origin !== 'dsh-app://app') return new Response(null, { status: 403 })
  const target = new URL(host)
  target.pathname = source.pathname
  target.search = source.search
  const headers = new Headers(request.headers)
  for (const name of ['host', 'origin', 'cookie', 'sec-fetch-site']) headers.delete(name)
  headers.set('cookie', cookie)
  const init = { method: request.method, headers, body: request.body, signal: request.signal, duplex: 'half', redirect: 'manual' as const }
  const response = await fetch(target, init)
  const outgoing = new Headers(response.headers)
  for (const name of WITHHELD_RESPONSE_HEADERS) outgoing.delete(name)
  if (PLUGIN_BUNDLE_PATH.test(source.pathname)) outgoing.set('cache-control', 'no-store')
  return new Response(response.body, { status: response.status, headers: outgoing })
}
