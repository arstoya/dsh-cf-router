/**
 * client-auth.mjs — 代理客户端认证与 RouteGroup 绑定（Issue #27 / B2）
 *
 * 方案 §5.4 的一条硬要求：**客户端身份只能由服务端认证结果确定**。
 *
 * ## 为什么不去读 x-client-id 之类的头
 *
 * 请求头完全由发起请求的一方控制。任何「头里有就信」的写法，等于把
 * 「我是哪个客户端、我该走哪个分组」的决定权交给了调用方 —— 只要手里有
 * 任意一个合法 Token，就能声称自己是别的客户端，跳到别人的 RouteGroup。
 * 所以这里的身份函数只有两个输入：Token 的 sha256、服务端配置的
 * `authTokenHash`。头里的自报字段不但不采信，还要在转发给上游之前剥掉
 * （`sanitizeIdentityHeaders`），否则上游可能误以为那些字段是可信的。
 *
 * ## 为什么只在内存里比哈希、明文永不落盘
 *
 * 明文 Token 只在 `generateClientToken()` 的返回值里出现一次，配置里存
 * sha256。这样即使配置文件或状态快照泄露，也拿不到可用凭据。比较走
 * `crypto.timingSafeEqual`：普通 `===` 在首个不同字节就返回，攻击者能靠
 * 响应时间逐字节猜出 Token。
 *
 * ## 为什么不做缓存
 *
 * 「禁用 / 轮换即时生效」是运维要求：把某个客户端 `enabled: false` 之后，
 * 手里还握着旧 Token 的调用方必须立刻失败。任何结果缓存、hash→client
 * 索引缓存都会把失效延迟到缓存过期，所以每次认证都重新遍历客户端集合。
 *
 * @module client-auth
 */

import crypto from 'node:crypto'

import { ClientUnauthorized } from './contract/errors.mjs'

/**
 * 服务端客户端表里的一条记录。**复用 A2 的定义，不在这里重新声明字段**，
 * 否则两边字段一漂移就会出现「配置通过了校验、认证却读不到」的对接错误。
 *
 * @typedef {import('./contract/upstream.mjs').ProxyClient} ProxyClient
 */

/**
 * 认证成功后返回的身份。
 *
 * 刻意只含这两个字段：`clientId` 用于日志与审计，`routeGroupId` 用于选路。
 * 不把 `authTokenHash`、`name` 之类带出去 —— 调用方拿不到就不需要判断
 * 「这个字段可信吗」。
 *
 * @typedef {object} ClientIdentity
 * @property {string} clientId
 * @property {string} routeGroupId
 */

/**
 * 客户端集合的三种合法形态。
 *
 * Map 的键是客户端 id（便于按 id 增删），数组/任意可迭代对象用于
 * 「配置里直接写一条列表」的场合。**必须是可变集合**：禁用与轮换依赖
 * 调用方替换集合里的元素，认证函数自己在每次调用时重新读取。
 *
 * @typedef {Map<string, ProxyClient> | ProxyClient[] | Iterable<ProxyClient> | null | undefined} ClientCollection
 */

/** 生成 Token 的随机字节数。32 字节 = 256 位熵，远超暴力猜测可行范围。 */
export const CLIENT_TOKEN_BYTES = 32

/**
 * 必须在转发前剥掉的「自报身份」头。
 *
 * 判据是「这个字段能不能改变谁的身份 / 走哪个分组」。`x-forwarded-for`
 * 刻意**不在**名单里：它是来源 IP，属于日志信息而不是身份，剥掉只会让
 * 审计缺数据；身份判定完全不读它，所以留着无害。
 */
export const CLIENT_IDENTITY_HEADERS = Object.freeze([
  'x-client-id',
  'x-client-name',
  'x-client-token',
  'x-route-group',
  'x-route-group-id',
  'x-forwarded-user',
  'x-forwarded-email',
  'x-auth-user',
  'x-remote-user',
  'x-user-id',
])

/** 用于 O(1) 判断某个头名是否属于「自报身份」 */
const IDENTITY_HEADER_SET = new Set(CLIENT_IDENTITY_HEADERS)

/**
 * 声明路由分组的头。与身份头分开列，是因为「忽略它的值」和「发现它跟
 * 服务端绑定冲突就拒绝」是两条不同的处理，需要能单独读出来。
 */
const CLAIMED_ROUTE_GROUP_HEADERS = Object.freeze(['x-route-group', 'x-route-group-id'])

/* ============================================================
 * 1. Token 生成与哈希
 * ============================================================ */

/**
 * 生成一个代理客户端 Token 及其配置用摘要。
 *
 * 用 `crypto.randomBytes` 而不是 `Math.random`：后者是可预测的 PRNG，
 * 种子一旦被推断出来，历史上所有 Token 都能被算出来。
 *
 * 明文只在本次返回值里出现一次 —— 调用方应立刻交给使用方并丢弃，
 * 配置里只写 `authTokenHash`。
 *
 * @returns {{ token: string, authTokenHash: string }}
 */
export function generateClientToken() {
  const token = crypto.randomBytes(CLIENT_TOKEN_BYTES).toString('base64url')
  return Object.freeze({ token, authTokenHash: hashClientToken(token) })
}

/**
 * 计算客户端 Token 的摘要。
 *
 * 固定 sha256 hex（长度 64）：正好满足 `makeProxyClient` 对
 * `authTokenHash` 的形态要求，也不会命中它的「明文 Token」启发式
 * （十六进制摘要会先被认出来，不会被当成 base64 key）。
 *
 * @param {string} token
 * @returns {string}
 * @throws {ClientUnauthorized} Token 为空或不是字符串
 */
export function hashClientToken(token) {
  if (typeof token !== 'string' || token === '') {
    throw new ClientUnauthorized('客户端凭据不能为空', { reason: 'empty_credential' })
  }
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex')
}

/**
 * 等长字符串的时序安全比较。
 *
 * 与 #8 的 `safeTokenEqual` 语义一致，但这里刻意不复用：client-auth 属于
 * 代理面，不依赖管理面模块可以避免两条链在后续重构时互相牵动。这里比较
 * 的永远是十六进制摘要，也不需要 #8 那套「非字符串 / 空值」的宽松兜底。
 *
 * 先比字节长度再进 `crypto.timingSafeEqual`：后者对不等长输入是抛
 * `RangeError`，不是返回 false。
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function constantTimeStringEqual(a, b) {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length === 0 || bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

/**
 * 比较「本次算出的摘要」与「配置里的摘要」。
 *
 * 长度不等直接 false，**不进入 timingSafeEqual** —— 一条长度被篡改的请求
 * 不该以 RangeError 结束，那会被上层当成 500 内部错误，而不是统一的
 * 401 认证失败，还会在异常路径上暴露实现细节。
 *
 * @param {string} computed 本次由 Token 计算的摘要
 * @param {string} expected 配置里的摘要
 * @returns {boolean}
 */
export function clientTokenHashMatches(computed, expected) {
  if (typeof computed !== 'string' || typeof expected !== 'string') return false
  if (computed === '' || expected === '') return false
  if (computed.length !== expected.length) return false
  return constantTimeStringEqual(computed, expected)
}

/* ============================================================
 * 2. 认证
 * ============================================================ */

/**
 * 客户端是否参与本次认证。
 *
 * 只认 `enabled === true`，字段缺失按禁用处理。理由是两种默认值的代价
 * 不对称：漏写字段导致凭据失效会被立刻发现；而「默认放行」会留下一条
 * 谁都没注意到、却一直可用的入口。
 *
 * @param {ProxyClient} client
 * @returns {boolean}
 */
function isEnabledClient(client) {
  if (client == null || typeof client !== 'object') return false
  if (client.enabled !== true) return false
  return typeof client.id === 'string' && client.id !== ''
    && typeof client.routeGroupId === 'string' && client.routeGroupId !== ''
}

/**
 * 把三种集合形态统一成数组。
 *
 * 每次调用都重新展开，不做记忆化 —— 这就是「禁用即时生效」的实现方式。
 *
 * @param {ClientCollection} clients
 * @returns {ProxyClient[]}
 */
function toClientList(clients) {
  if (clients == null) return []
  if (clients instanceof Map) return [...clients.values()]
  if (Array.isArray(clients)) return clients
  // 任意可迭代对象都接受（Set、生成器等）。这里刻意用 any：
  // 「是不是可迭代」本身就是运行时判断，写死成某个接口只会多一次无效的静态假设。
  const maybeIterable = /** @type {any} */ (clients)
  if (typeof maybeIterable === 'object' && typeof maybeIterable[Symbol.iterator] === 'function') {
    return [.../** @type {Iterable<ProxyClient>} */ (maybeIterable)]
  }
  return []
}

/**
 * 大小写不敏感地取一个请求头的值。
 *
 * HTTP 头名大小写不敏感，但普通对象的键是敏感的：只按小写找会漏掉
 * `Authorization`、只按驼峰找会漏掉 `authorization`。数组值取第一个
 * 非空字符串（Node 对重复头会合并成数组）。
 *
 * @param {Record<string, unknown>} headers
 * @param {readonly string[]} names 小写头名
 * @returns {string}
 */
function pickHeader(headers, names) {
  const wanted = new Set(names)
  for (const [key, value] of Object.entries(headers)) {
    if (!wanted.has(key.toLowerCase())) continue
    if (typeof value === 'string' && value.trim() !== '') return value.trim()
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && item.trim() !== '') return item.trim()
      }
    }
  }
  return ''
}

/**
 * 从 `Authorization: Bearer <token>` 里取 Token。
 *
 * 严格匹配整个头：多余的空格可以，多出来的 token 不行。`Bearer a Bearer b`
 * 这种畸形头必须整体判失败，而不是取第一个 `\S+` —— 宽松解析会让
 * 「头部拼接攻击」变成可能。
 *
 * 参数既接受单个头字符串，也接受整个 headers 对象（调用方通常手里是后者）。
 *
 * @param {string | Record<string, unknown> | null | undefined} authorizationHeader
 * @returns {string} 取不到时返回空串
 */
function extractBearerToken(authorizationHeader) {
  let raw = ''
  if (typeof authorizationHeader === 'string') raw = authorizationHeader
  else if (authorizationHeader && typeof authorizationHeader === 'object') {
    raw = pickHeader(/** @type {Record<string, unknown>} */ (authorizationHeader), ['authorization'])
  }
  if (raw === '') return ''
  const matched = /^\s*bearer\s+(\S+)\s*$/i.exec(raw)
  return matched ? matched[1] : ''
}

/**
 * 用 Bearer 凭据认证客户端。
 *
 * 返回值里的 `clientId` / `routeGroupId` **全部来自服务端配置**，是这个
 * 请求身份的唯一来源。函数完全不读 `x-client-id` / `x-route-group` /
 * `x-forwarded-user`，即使传进来的是整个 headers 对象。
 *
 * @param {string | Record<string, unknown> | null | undefined} authorizationHeader
 * @param {ClientCollection} clients
 * @returns {ClientIdentity}
 * @throws {ClientUnauthorized} 凭据缺失、无法解析、不匹配，或同一凭据绑定到多个客户端
 */
export function authenticateClient(authorizationHeader, clients) {
  const token = extractBearerToken(authorizationHeader)
  if (token === '') {
    throw new ClientUnauthorized('缺少可用的 Bearer 凭据', { reason: 'missing_credential' })
  }

  const digest = hashClientToken(token)

  /** @type {ProxyClient[]} */
  const matched = []
  for (const client of toClientList(clients)) {
    if (!isEnabledClient(client)) continue
    if (!clientTokenHashMatches(digest, client.authTokenHash)) continue
    matched.push(client)
  }

  if (matched.length === 0) {
    // 不区分「没有这个客户端」和「哈希不匹配」：错误信息越少，越难通过
    // 反复试探确认某个客户端是否存在。
    throw new ClientUnauthorized('客户端凭据无效', { reason: 'token_mismatch' })
  }

  if (matched.length > 1) {
    // 同一 Token 绑到多个客户端时身份不唯一，无法确定该走哪个分组。
    // 这属于配置错误，宁可全部拒绝，也不要随便挑一个。
    throw new ClientUnauthorized('多个启用客户端共用同一凭据，无法确定身份', {
      reason: 'ambiguous_identity',
      matches: matched.length,
    })
  }

  const client = matched[0]
  return Object.freeze({ clientId: client.id, routeGroupId: client.routeGroupId })
}

/* ============================================================
 * 3. 拒绝客户端自报身份
 * ============================================================ */

/**
 * 剥掉请求头里的「自报身份」字段。
 *
 * 约定（调用方必须遵守）：转发到上游之前先过这个函数，并且**只使用它
 * 返回的 headers**。原始 headers 里的 `x-client-id` / `x-route-group` /
 * `x-forwarded-user` 之类字段既不能参与身份判定，也不能被透传给上游 ——
 * 上游一旦看到它们，就可能把它们当成已经过认证的标识。
 *
 * `removed` 返回被剥掉的头名（去重后的小写形式），供日志审计定位
 * 「谁在冒充」。名单本身不含值：值可能是攻击载荷，进日志会变成注入点。
 *
 * @param {Record<string, unknown> | null | undefined} headers
 * @returns {{ headers: Record<string, unknown>, removed: string[] }}
 */
export function sanitizeIdentityHeaders(headers) {
  /** @type {Record<string, unknown>} */
  const kept = {}
  /** @type {string[]} */
  const removed = []

  if (headers && typeof headers === 'object') {
    for (const [key, value] of Object.entries(headers)) {
      const lower = key.toLowerCase()
      if (IDENTITY_HEADER_SET.has(lower)) {
        if (!removed.includes(lower)) removed.push(lower)
        continue
      }
      kept[key] = value
    }
  }

  return { headers: kept, removed }
}

/**
 * 校验「请求头声明的分组」与「服务端绑定」是否一致。
 *
 * 语义是：**声明不参与任何决策**，但如果声明与服务端事实冲突，说明调用方
 * 以为自己在另一个分组（通常是配置抄错、或有人在试探越权），此时直接
 * 拒绝比静默按服务端绑定执行更容易被发现。声明为空（绝大多数正常请求）
 * 时什么都不做。
 *
 * @param {ClientIdentity} identity
 * @param {string | null | undefined} claimedRouteGroupId
 * @returns {ClientIdentity}
 * @throws {ClientUnauthorized} 声明值与服务端绑定不一致
 */
export function assertRouteGroupBinding(identity, claimedRouteGroupId) {
  const claimed = typeof claimedRouteGroupId === 'string' ? claimedRouteGroupId.trim() : ''
  if (claimed === '') return identity
  if (claimed !== identity.routeGroupId) {
    throw new ClientUnauthorized('请求头声明的路由分组与服务端绑定不一致', {
      reason: 'route_group_mismatch',
      // 截断后再进 details：这是外部可控字符串，不设上限会让日志出现超长行。
      requestedRouteGroupId: claimed.slice(0, 64),
    })
  }
  return identity
}

/**
 * 一次请求的完整认证入口：剥头 → 认证 → 校验分组声明。
 *
 * 用这个而不是自己拼三步，是为了让「先剥再认证」的顺序无法被漏掉；
 * 顺带把被剥掉的头名带回去，调用方可以直接写审计日志。
 *
 * @param {Record<string, unknown> | null | undefined} headers
 * @param {ClientCollection} clients
 * @returns {ClientIdentity & { removedHeaders: readonly string[] }}
 * @throws {ClientUnauthorized}
 */
export function authenticateRequest(headers, clients) {
  const source = headers && typeof headers === 'object' ? headers : {}
  const claimed = pickHeader(source, CLAIMED_ROUTE_GROUP_HEADERS)
  const { headers: clean, removed } = sanitizeIdentityHeaders(source)
  const identity = assertRouteGroupBinding(authenticateClient(clean, clients), claimed)
  return Object.freeze({
    clientId: identity.clientId,
    routeGroupId: identity.routeGroupId,
    removedHeaders: Object.freeze(removed.slice()),
  })
}

/* ============================================================
 * 4. 身份分离：代理凭据不得用于管理面
 * ============================================================ */

/**
 * 断言「代理客户端凭据」不是「管理凭据」。
 *
 * 同一条 Token 两种用途，会把「某个代理客户端泄露」直接升级成「管理面
 * 泄露」—— 而两者本来是完全不同量级的权限。所以复用本身当作配置错误
 * 拒绝，而不是只靠权限位去限制。
 *
 * `adminToken` 为空表示管理端点没有配置凭据（此时管理面本就不可用），
 * 这种情况下不做分离检查，否则会让未启用管理接口的部署无法下发客户端 Token。
 *
 * @param {string} token 代理客户端这边的明文 Token（来自请求）
 * @param {string | null | undefined} adminToken 当前生效的管理 Token
 * @returns {true}
 * @throws {ClientUnauthorized} token 为空，或与 adminToken 相同
 */
export function assertNotAdminToken(token, adminToken) {
  const provided = typeof token === 'string' ? token : ''
  if (provided === '') {
    throw new ClientUnauthorized('缺少客户端凭据', { reason: 'missing_credential' })
  }
  const admin = typeof adminToken === 'string' ? adminToken.trim() : ''
  if (admin !== '' && constantTimeStringEqual(provided, admin)) {
    throw new ClientUnauthorized('代理客户端凭据不得用于管理端点', { reason: 'credential_reuse' })
  }
  return true
}
