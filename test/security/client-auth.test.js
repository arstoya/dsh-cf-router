/**
 * client-auth.test.js — 代理客户端认证与 RouteGroup 绑定（Issue #27 / B2）
 *
 * 十条用例对着方案 §5.4 的硬要求逐条落：
 *   1 正确 Token 成功 2 错误 Token 失败 3 缺头 4 畸形头
 *   5 自报 x-client-id 被忽略 6 跨客户端越权绑定被拒
 *   7 禁用即时生效 8 代理凭据不得进管理面
 *   9 配置里只落哈希 10 长度不同的摘要不触发 RangeError
 *
 * 关键立场：身份必须是 f(Token, 服务端客户端表)，请求头里的任何自报字段
 * 都不能改变返回值。所以第 5、6 条断言的正是「返回值不等于头里写的」。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  CLIENT_IDENTITY_HEADERS,
  assertNotAdminToken,
  assertRouteGroupBinding,
  authenticateClient,
  authenticateRequest,
  clientTokenHashMatches,
  generateClientToken,
  hashClientToken,
  sanitizeIdentityHeaders,
} from '../../lib/client-auth.mjs'
import { makeProxyClient } from '../../lib/contract/upstream.mjs'
import { ClientUnauthorized } from '../../lib/contract/errors.mjs'

/* ============================================================
 * 夹具
 * ============================================================ */

/**
 * 两个客户端 + 各自的 Token。用 makeProxyClient 构造，保证夹具与生产配置
 * 走同一套校验：如果哪天契约改了字段，这里会第一时间炸。
 */
function fixture() {
  const a = generateClientToken()
  const b = generateClientToken()
  /** @type {Map<string, import('../../lib/contract/upstream.mjs').ProxyClient>} */
  const clients = new Map()
  clients.set('client-a', makeProxyClient({
    id: 'client-a', name: '甲客户端', routeGroupId: 'group-a', authTokenHash: a.authTokenHash,
  }))
  clients.set('client-b', makeProxyClient({
    id: 'client-b', name: '乙客户端', routeGroupId: 'group-b', authTokenHash: b.authTokenHash,
  }))
  return { clients, tokenA: a.token, tokenB: b.token, hashA: a.authTokenHash, hashB: b.authTokenHash }
}

/**
 * 断言某个调用以 ClientUnauthorized 结束，并把错误对象带回去。
 *
 * 用 try/catch 而不是 assert.throws 的验证函数：验证函数里再抛 assert 错误时，
 * node:test 的报错信息会把「为什么失败」埋掉，只剩一句「验证函数抛错」。
 */
function expectUnauthorized(fn, secret) {
  /** @type {any} */
  let caught = null
  try {
    fn()
  } catch (err) {
    caught = err
  }
  assert.ok(caught !== null, '应当抛错，实际正常返回')
  assert.ok(caught instanceof ClientUnauthorized, `应当是 ClientUnauthorized，实际 ${caught && caught.name}`)
  assert.equal(caught.code, 'client_unauthorized')
  // 序列化结果里不得出现凭据本体：错误会被写进日志，日志就是泄露渠道
  if (secret) {
    const serialized = JSON.stringify(caught)
    assert.ok(!serialized.includes(secret), '错误详情不得回显凭据')
    assert.ok(!serialized.includes('authorization'), '错误详情不得回显 Authorization 头')
  }
  return caught
}

/* ============================================================
 * 1. 正确 Token
 * ============================================================ */

test('正确 Token 认证成功，返回服务端绑定的 clientId / routeGroupId', () => {
  const { clients, tokenA } = fixture()

  const identity = authenticateClient(`Bearer ${tokenA}`, clients)
  assert.deepEqual({ ...identity }, { clientId: 'client-a', routeGroupId: 'group-a' })
  assert.ok(Object.isFrozen(identity), '身份对象应冻结：调用方改写它不该影响后续请求')

  // 也接受整个 headers 对象，大小写两种写法都要认
  assert.equal(authenticateClient({ authorization: `Bearer ${tokenA}` }, clients).clientId, 'client-a')
  assert.equal(authenticateClient({ Authorization: `Bearer ${tokenA}` }, clients).clientId, 'client-a')

  // 数组形态的集合同样可用
  const asArray = [...clients.values()]
  assert.equal(authenticateClient(`Bearer ${tokenA}`, asArray).routeGroupId, 'group-a')
})

/* ============================================================
 * 2. 错误 Token
 * ============================================================ */

test('错误 Token 认证失败', () => {
  const { clients, tokenA } = fixture()

  // 长度不同
  const tooLong = expectUnauthorized(() => authenticateClient(`Bearer ${tokenA}x`, clients), tokenA)
  assert.equal(tooLong.details.reason, 'token_mismatch')
  // 长度相同但内容不同（首字符换掉）
  const flipped = `${tokenA[0] === 'A' ? 'B' : 'A'}${tokenA.slice(1)}`
  const err = expectUnauthorized(() => authenticateClient(`Bearer ${flipped}`, clients), tokenA)
  assert.equal(err.details.reason, 'token_mismatch')

  // 同一个 Token 只认自己那条记录：拿 A 的 Token 不会匹配到 B
  assert.equal(authenticateClient(`Bearer ${tokenA}`, clients).clientId, 'client-a')
  // 客户端表为空
  expectUnauthorized(() => authenticateClient(`Bearer ${tokenA}`, []))
  expectUnauthorized(() => authenticateClient(`Bearer ${tokenA}`, null))
})

/* ============================================================
 * 3. 缺失 Authorization
 * ============================================================ */

test('缺失 Authorization 头直接失败', () => {
  const { clients } = fixture()
  for (const missing of [undefined, null, '', {}, { authorization: '' }, { authorization: '   ' }]) {
    const err = expectUnauthorized(() => authenticateClient(/** @type {any} */ (missing), clients))
    assert.equal(err.details.reason, 'missing_credential')
  }
})

/* ============================================================
 * 4. 畸形头
 * ============================================================ */

test('畸形 Authorization 头一律失败，不做宽松解析', () => {
  const { clients, tokenA, tokenB } = fixture()
  const malformed = [
    'Bearer',                       // Bearer 后为空
    'Bearer ',                      // 只有空白
    'Bearer        ',               // 多个空白后仍为空
    'Basic ' + tokenA,              // 方案不对
    tokenA,                         // 裸 Token，没有 Bearer 前缀
    `Bearer ${tokenA} ${tokenB}`,   // 两个 Token 拼接
    `Bearer ${tokenA} Bearer ${tokenB}`, // 多个 Bearer
    `Bearer ` + tokenA + ' extra',  // 尾部多余片段
  ]
  for (const value of malformed) {
    const err = expectUnauthorized(() => authenticateClient(value, clients))
    assert.equal(err.details.reason, 'missing_credential', `畸形头应判为缺失凭据：${value}`)
  }
})

/* ============================================================
 * 5. 自报 x-client-id 被忽略
 * ============================================================ */

test('客户端自报 x-client-id / x-route-group 被忽略，身份只来自 Token', () => {
  const { clients, tokenA, tokenB } = fixture()

  // 拿 B 的 Token，同时声称自己是 A —— 返回值必须是 B
  const identity = authenticateRequest({
    authorization: `Bearer ${tokenB}`,
    'x-client-id': 'client-a',
    'x-client-name': '甲客户端',
    'x-forwarded-user': 'root',
  }, clients)

  assert.equal(identity.clientId, 'client-b', '身份必须来自 Token，不是 x-client-id')
  assert.equal(identity.routeGroupId, 'group-b', '分组必须来自服务端绑定')
  assert.deepEqual([...identity.removedHeaders].sort(), ['x-client-id', 'x-client-name', 'x-forwarded-user'])

  // 即使头里写了别的分组，authenticateClient 也完全不读
  const fromHeader = authenticateClient({ authorization: `Bearer ${tokenA}`, 'x-route-group': 'group-b' }, clients)
  assert.equal(fromHeader.routeGroupId, 'group-a', '头里的分组不得改变服务端绑定')
})

test('sanitizeIdentityHeaders 剥掉自报身份头并返回名单，保留其它头', () => {
  const { headers, removed } = sanitizeIdentityHeaders({
    authorization: 'Bearer abc',
    'X-Client-Id': 'client-a',
    'x-route-group': 'group-b',
    'x-forwarded-user': 'root',
    'x-forwarded-for': '203.0.113.9',
    'content-type': 'application/json',
  })

  assert.deepEqual(removed.slice().sort(), ['x-client-id', 'x-forwarded-user', 'x-route-group'])
  assert.equal(headers.authorization, 'Bearer abc', '认证凭据不能被剥')
  assert.equal(headers['content-type'], 'application/json')
  assert.equal(headers['x-forwarded-for'], '203.0.113.9', '来源 IP 不是身份，保留给日志')
  for (const key of Object.keys(headers)) {
    assert.ok(!CLIENT_IDENTITY_HEADERS.includes(key.toLowerCase()), `身份头 ${key} 不该留下来`)
  }

  // 空输入也要给稳定的形状，调用方不必判空
  assert.deepEqual(sanitizeIdentityHeaders(undefined), { headers: {}, removed: [] })
  assert.deepEqual(sanitizeIdentityHeaders(null), { headers: {}, removed: [] })
})

/* ============================================================
 * 6. 跨客户端越权绑定 RouteGroup
 * ============================================================ */

test('跨客户端越权声明 RouteGroup 被拒', () => {
  const { clients, tokenA, tokenB } = fixture()

  // A 的凭据声明走 B 的分组 → 拒绝（而不是静默忽略后按 A 执行）
  const err = expectUnauthorized(() => authenticateRequest({
    authorization: `Bearer ${tokenA}`,
    'x-route-group': 'group-b',
  }, clients), tokenA)
  assert.equal(err.details.reason, 'route_group_mismatch')
  assert.equal(err.details.requestedRouteGroupId, 'group-b')

  // B 的凭据声明走 A 的分组，同样拒绝
  expectUnauthorized(() => authenticateRequest({
    authorization: `Bearer ${tokenB}`,
    'x-route-group-id': 'group-a',
  }, clients))

  // 声明自己真实的分组时放行，且返回值仍是服务端绑定
  const ok = authenticateRequest({ authorization: `Bearer ${tokenA}`, 'x-route-group': 'group-a' }, clients)
  assert.equal(ok.clientId, 'client-a')
  assert.equal(ok.routeGroupId, 'group-a')

  // 绑定校验函数单独可用；空声明 = 不表态，直接通过
  expectUnauthorized(() => assertRouteGroupBinding({ clientId: 'client-a', routeGroupId: 'group-a' }, 'group-b'))
  assert.deepEqual(
    { ...assertRouteGroupBinding({ clientId: 'client-a', routeGroupId: 'group-a' }, '') },
    { clientId: 'client-a', routeGroupId: 'group-a' },
  )
  assert.deepEqual(
    { ...assertRouteGroupBinding({ clientId: 'client-a', routeGroupId: 'group-a' }, null) },
    { clientId: 'client-a', routeGroupId: 'group-a' },
  )
})

/* ============================================================
 * 7. 禁用与轮换即时生效
 * ============================================================ */

test('disabled 的客户端立即失效，轮换后旧 Token 立刻作废', () => {
  const first = generateClientToken()
  /** @type {Map<string, any>} */
  const clients = new Map()
  clients.set('c1', makeProxyClient({ id: 'c1', routeGroupId: 'g1', authTokenHash: first.authTokenHash }))

  assert.equal(authenticateClient(`Bearer ${first.token}`, clients).clientId, 'c1')

  // 同一个 Map 里替换一条 enabled:false —— 下一次调用就必须失败（无缓存）
  clients.set('c1', makeProxyClient({
    id: 'c1', routeGroupId: 'g1', authTokenHash: first.authTokenHash, enabled: false,
  }))
  const disabledErr = expectUnauthorized(() => authenticateClient(`Bearer ${first.token}`, clients))
  assert.equal(disabledErr.details.reason, 'token_mismatch', '禁用后的失败与凭据错误同形，不暴露客户端是否存在')

  // 轮换：换成新摘要后，旧 Token 失效，新 Token 可用
  const second = generateClientToken()
  clients.set('c1', makeProxyClient({ id: 'c1', routeGroupId: 'g1', authTokenHash: second.authTokenHash }))
  expectUnauthorized(() => authenticateClient(`Bearer ${first.token}`, clients))
  assert.equal(authenticateClient(`Bearer ${second.token}`, clients).clientId, 'c1')
})

test('集合元素缺 enabled 时按禁用处理（默认拒绝，不留静默入口）', () => {
  const generated = generateClientToken()
  // 手工对象：有 id / routeGroupId / authTokenHash，但没有 enabled
  const bare = [{ id: 'c9', routeGroupId: 'g9', authTokenHash: generated.authTokenHash }]
  expectUnauthorized(() => authenticateClient(`Bearer ${generated.token}`, /** @type {any} */ (bare)))

  // 显式 enabled:true 才放行
  const enabled = [{ ...bare[0], enabled: true }]
  assert.equal(authenticateClient(`Bearer ${generated.token}`, /** @type {any} */ (enabled)).clientId, 'c9')
})

test('同一凭据绑定到多个启用客户端时拒绝认证（身份必须唯一）', () => {
  const shared = generateClientToken()
  const clients = [
    makeProxyClient({ id: 'dup-1', routeGroupId: 'group-1', authTokenHash: shared.authTokenHash }),
    makeProxyClient({ id: 'dup-2', routeGroupId: 'group-2', authTokenHash: shared.authTokenHash }),
  ]
  const err = expectUnauthorized(() => authenticateClient(`Bearer ${shared.token}`, clients))
  assert.equal(err.details.reason, 'ambiguous_identity')

  // 把其中一个禁用后身份重新唯一，认证恢复
  const oneDisabled = [clients[0], makeProxyClient({
    id: 'dup-2', routeGroupId: 'group-2', authTokenHash: shared.authTokenHash, enabled: false,
  })]
  assert.equal(authenticateClient(`Bearer ${shared.token}`, oneDisabled).clientId, 'dup-1')
})

/* ============================================================
 * 8. 代理凭据不能进管理面
 * ============================================================ */

test('代理 Token 不能用于管理端点', () => {
  const { tokenA } = fixture()

  // 与管理 Token 不同 → 放行
  assert.equal(assertNotAdminToken(tokenA, 'an-entirely-different-admin-token'), true)

  // 同一个 Token 两种用途 → 直接拒绝
  const err = expectUnauthorized(() => assertNotAdminToken(tokenA, tokenA))
  assert.equal(err.details.reason, 'credential_reuse')

  // 前后空白不该造成「看起来不同」的漏判
  expectUnauthorized(() => assertNotAdminToken(tokenA, `  ${tokenA}  `))

  // 空凭据本身也不合法
  expectUnauthorized(() => assertNotAdminToken('', tokenA))

  // 管理端点未配置 Token 时不做分离检查，否则没启用管理面的部署无法下发客户端凭据
  assert.equal(assertNotAdminToken(tokenA, ''), true)
  assert.equal(assertNotAdminToken(tokenA, null), true)
})

/* ============================================================
 * 9. 配置里只落哈希
 * ============================================================ */

test('生成结果只含哈希：返回值不等于 Token，且能通过 makeProxyClient 校验', () => {
  const { token, authTokenHash } = generateClientToken()

  assert.notEqual(authTokenHash, token, '摘要不得等于明文')
  assert.equal(authTokenHash.length, 64, 'sha256 hex 长度应为 64')
  assert.match(authTokenHash, /^[0-9a-f]{64}$/, '必须是十六进制摘要')
  assert.ok(!authTokenHash.includes(token), '摘要里不该出现明文片段')
  assert.ok(!token.includes(authTokenHash), '明文里自然也不该含摘要')

  // 摘要稳定：同一个 Token 算两次结果相同
  assert.equal(hashClientToken(token), authTokenHash)

  // 能直接喂给契约层的工厂函数（形态校验通过，不会被当成明文 Token）
  const client = makeProxyClient({ id: 'hashed', routeGroupId: 'group-x', authTokenHash })
  assert.equal(client.authTokenHash, authTokenHash)

  // 两次生成必须不同
  assert.notEqual(generateClientToken().token, token)
})

/* ============================================================
 * 10. 长度不同的摘要不进入 timingSafeEqual
 * ============================================================ */

test('长度不同的摘要直接返回 false，不抛 RangeError', () => {
  const token = generateClientToken().token
  const digest = hashClientToken(token)

  assert.equal(clientTokenHashMatches(digest, digest), true)
  assert.equal(clientTokenHashMatches(digest, digest.slice(0, 32)), false, '短一半的假 hash')
  assert.equal(clientTokenHashMatches(digest, `${digest}00`), false, '长两位的假 hash')
  assert.equal(clientTokenHashMatches(digest, 'deadbeef'), false, '明显不是摘要的假 hash')
  assert.equal(clientTokenHashMatches('', digest), false)
  assert.equal(clientTokenHashMatches(digest, ''), false)
  assert.equal(clientTokenHashMatches(/** @type {any} */ (null), digest), false)
  assert.equal(clientTokenHashMatches(digest, /** @type {any} */ (undefined)), false)

  // 认证路径上：配置里放畸形长度 / 值不对的摘要，都走统一的认证失败
  expectUnauthorized(() => authenticateClient(`Bearer ${token}`, [
    { id: 'short', name: 'short', enabled: true, routeGroupId: 'g', authTokenHash: 'deadbeef' },
  ]))
  expectUnauthorized(() => authenticateClient(`Bearer ${token}`, [
    { id: 'wrong', name: 'wrong', enabled: true, routeGroupId: 'g', authTokenHash: 'f'.repeat(64) },
  ]))
})
