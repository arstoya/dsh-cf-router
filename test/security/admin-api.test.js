/**
 * admin-api.test.js — 管理 API 授权、校验、脱敏与审计（v0.4.0 / B3）
 *
 * 覆盖方案 §5.9 的四项要求（独立管理员身份、方法限制、schema 校验、审计日志），
 * 外加分页、乐观锁与删除引用检查。每条断言都对着「泄露 / 静默忽略 / 越界」这三类
 * 最容易犯的错来写，而不是对着实现细节。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  createAdminGuard,
  validateAdminRequest,
  redactForLog,
  redactForResponse,
  makeAuditEntry,
  paginate,
  checkVersion,
  assertNotReferenced,
  ADMIN_METHODS,
  PAGINATION,
} from '../../lib/admin-api.mjs'

/* ============================================================
 * 公共夹具
 * ============================================================ */

const TOKEN = 'unit-test-admin-token-0123456789'
const LOOPBACK_HOST = '127.0.0.1:8787'

/** 一个合法的管理请求（回环 Host、无 Origin、带正确 Bearer） */
function makeReq(overrides = {}) {
  // headers 必须单独合并：直接 `...overrides` 会把整个 headers 换掉，
  // 于是「只换 authorization」的用例会连 host 一起丢掉，四处报成 forbidden_host。
  const { headers: extraHeaders, ...rest } = overrides
  return {
    remoteAddr: '127.0.0.1',
    route: '/__router/admin/upstreams',
    ...rest,
    headers: {
      host: LOOPBACK_HOST,
      authorization: `Bearer ${TOKEN}`,
      ...(extraHeaders || {}),
    },
  }
}

/** 断言某个判定抛出的是 contract 层的 ClientUnauthorized，并带预期 status */
function assertDenied(fn, status, reason) {
  assert.throws(fn, (err) => {
    assert.equal(err.code, 'client_unauthorized', `code 应为 client_unauthorized，实际 ${err.code}`)
    assert.equal(err.name, 'ClientUnauthorized')
    assert.equal(err.details.status, status, `status 应为 ${status}，实际 ${err.details.status}`)
    if (reason) assert.equal(err.details.reason, reason)
    return true
  })
}

/* ============================================================
 * 一、管理员身份
 * ============================================================ */

test('1. 无凭据：拒绝，且不给「Token 对不对」的信息', () => {
  const guard = createAdminGuard({ token: TOKEN })
  const req = makeReq()
  delete req.headers.authorization

  assertDenied(() => guard.authorize(req), 401, 'unauthorized')
  assert.equal(guard.stats().unauthorized, 1)
  assert.equal(guard.stats().authorized, 0)
})

test('2. 错误凭据：拒绝，错误信息里不出现任何 Token 片段', () => {
  const guard = createAdminGuard({ token: TOKEN })
  const wrong = 'unit-test-admin-token-012345678X'

  let captured = null
  try {
    guard.authorize(makeReq({ headers: { authorization: `Bearer ${wrong}` } }))
  } catch (err) {
    captured = err
  }
  assert.ok(captured, '必须抛错')
  assert.equal(captured.code, 'client_unauthorized')
  assert.equal(captured.details.status, 401)

  const serialized = JSON.stringify(captured)
  assert.ok(!serialized.includes(wrong), '错误序列化里不得含提交的 Token')
  assert.ok(!serialized.includes(TOKEN), '错误序列化里不得含正确 Token')
})

test('3. 正确凭据：通过并返回 adminId（多管理员各自认得自己）', () => {
  const guard = createAdminGuard({
    credentials: [
      { adminId: 'ops', token: TOKEN },
      { adminId: 'auditor', token: 'second-admin-token-abcdefgh' },
    ],
  })

  assert.deepEqual(guard.authorize(makeReq()), { adminId: 'ops' })
  assert.deepEqual(
    guard.authorize(makeReq({ headers: { authorization: 'Bearer second-admin-token-abcdefgh' } })),
    { adminId: 'auditor' },
  )
  assert.equal(guard.stats().authorized, 2)

  // 单管理员模式也要有明确的身份
  const single = createAdminGuard({ token: TOKEN, adminId: 'solo' })
  assert.deepEqual(single.authorize(makeReq()), { adminId: 'solo' })
})

test('3b. Host / Origin 各自独立拒绝（不与凭据判定混在一起）', () => {
  const guard = createAdminGuard({ token: TOKEN, listenHost: '127.0.0.1', allowedOrigins: ['http://localhost:59906'] })

  // DNS rebinding：监听回环却收到外部 Host
  assertDenied(() => guard.authorize(makeReq({ headers: { host: 'evil.example' } })), 403, 'forbidden_host')
  assert.equal(guard.stats().deniedHost, 1)

  // 浏览器跨站
  assertDenied(
    () => guard.authorize(makeReq({ headers: { origin: 'http://evil.example' } })),
    403,
    'forbidden_origin',
  )

  // 白名单内的来源放行
  assert.deepEqual(
    guard.authorize(makeReq({ headers: { origin: 'http://localhost:59906' } })),
    { adminId: 'admin' },
  )
})

/* ============================================================
 * 四、失败认证限速
 * ============================================================ */

test('4. 失败限速：连续 N 次后拒绝，窗口过去后恢复', () => {
  let clock = 1_000_000
  const guard = createAdminGuard({
    token: TOKEN,
    maxFailures: 3,
    windowMs: 1000,
    now: () => clock,
  })

  const bad = () => guard.authorize(makeReq({ headers: { authorization: 'Bearer nope-nope-nope' } }))

  // 前 3 次是「凭据不对」→ 401
  for (let i = 1; i <= 3; i += 1) {
    assertDenied(bad, 401)
    assert.equal(guard.stats().rateLimited, 0, `第 ${i} 次不应被限速`)
  }

  // 第 4 次：闸门先拦，给出 429 与 retryAfterMs，而不是继续 401
  assertDenied(bad, 429, 'rate_limited')
  assert.equal(guard.stats().rateLimited, 1)

  // 超限期间即使凭据正确也不放行 —— 这是「先闸后验」的直接后果
  assertDenied(() => guard.authorize(makeReq()), 429, 'rate_limited')

  // 窗口过去后同一个来源恢复
  clock += 1001
  assert.deepEqual(guard.authorize(makeReq()), { adminId: 'admin' })
})

test('4b. 成功认证会清空该窗口的失败计数', () => {
  const clock = 5_000
  const guard = createAdminGuard({ token: TOKEN, maxFailures: 3, windowMs: 60_000, now: () => clock })
  const bad = (n) => () => guard.authorize(makeReq({ headers: { authorization: `Bearer wrong-${n}` } }))

  // 先攒 2 次失败（count=2），再用正确凭据通过（count=3 仍在上限内，随后清零）
  assertDenied(bad(1), 401)
  assertDenied(bad(2), 401)
  assert.deepEqual(guard.authorize(makeReq()), { adminId: 'admin' })

  // 若没有清零，下面第一次失败就是 count=4 直接 429；实际应为 401（count 从 1 重新数）
  assertDenied(bad(3), 401)
  assertDenied(bad(4), 401)
  assertDenied(bad(5), 401)
  // 第四次失败才撞上限
  assertDenied(bad(6), 429, 'rate_limited')

  assert.equal(guard.stats().unauthorized, 5)
  assert.equal(guard.stats().rateLimited, 1)
  assert.equal(guard.stats().authorized, 1)
})

test('4c. 未配置 Token 时不静默放行', () => {
  const guard = createAdminGuard({})
  assertDenied(() => guard.authorize(makeReq()), 401, 'unauthorized')
})

/* ============================================================
 * 五、六、七、脱敏
 * ============================================================ */

/** 覆盖题面要求的全部形态：Authorization 头、Cookie 头、apiKey 字段、三层嵌套 */
function makeSensitiveFixture() {
  return {
    headers: {
      Authorization: 'Bearer sk-live-TOPSECRET-bearer-value',
      Cookie: 'sid=abc123def456; theme=dark',
      'Set-Cookie': ['session=zzz999yyy; HttpOnly', 'other=qqq888'],
      host: '127.0.0.1:8787',
    },
    body: {
      apiKey: 'sk-xxx-FAKE-KEY-123456',
      authTokenHash: 'sha256-deadbeefcafe',
      adminToken: 'admin-token-plaintext-value',
      password: 'p@ssw0rd-should-not-leak',
      secret: 'client-secret-value',
      name: 'upstream-a',
      // 三层嵌套
      level1: {
        level2: {
          level3: {
            token: 'deep-nested-token-value',
            note: '这个字段不是敏感值，应当保留',
          },
        },
      },
    },
  }
}

/** 所有绝不允许出现在产物里的原文 */
const FORBIDDEN_FRAGMENTS = [
  'sk-live-TOPSECRET-bearer-value',
  'abc123def456',
  'zzz999yyy',
  'qqq888',
  'sk-xxx-FAKE-KEY-123456',
  'sha256-deadbeefcafe',
  'admin-token-plaintext-value',
  'p@ssw0rd-should-not-leak',
  'client-secret-value',
  'deep-nested-token-value',
]

test('5. redactForLog 不泄露：序列化结果不含任何原文，但保留结构线索', () => {
  const input = makeSensitiveFixture()
  const out = redactForLog(input)
  const json = JSON.stringify(out)

  for (const fragment of FORBIDDEN_FRAGMENTS) {
    assert.ok(!json.includes(fragment), `日志脱敏后仍含原文片段：${fragment}`)
  }

  // 结构线索保留：认证方案名、cookie 名可读，否则日志失去排查价值
  assert.match(json, /Bearer \[REDACTED\]/, '认证方案名应保留')
  assert.match(json, /sid=\[REDACTED\]/, 'cookie 名应保留、值被遮盖')
  assert.match(json, /theme=\[REDACTED\]/)
  assert.match(json, /这个字段不是敏感值，应当保留/, '非敏感字段必须原样保留')
  assert.match(json, /upstream-a/)
  assert.match(json, /127\.0\.0\.1:8787/, 'Host 不是敏感值')
})

test('6. redactForResponse 不泄露：同一条数据也不能从响应侧漏出去', () => {
  const input = makeSensitiveFixture()
  const out = redactForResponse(input)
  const json = JSON.stringify(out)

  for (const fragment of FORBIDDEN_FRAGMENTS) {
    assert.ok(!json.includes(fragment), `响应脱敏后仍含原文片段：${fragment}`)
  }
  // 响应侧比日志侧更严：连方案名与 cookie 名都不返回
  assert.ok(!json.includes('Bearer'), '响应不应回显认证方案')
  assert.ok(!json.includes('sid='), '响应不应回显 cookie 名')
  assert.ok(json.includes('[REDACTED]'))
})

test('6b. 数组与嵌套对象递归处理；Date / Error / 循环引用都可序列化', () => {
  const cyclic = { name: 'loop', token: 'cyclic-token-value' }
  cyclic.self = cyclic

  const input = {
    list: [
      { cookie: 'a=1' },
      { nested: [{ apiKey: 'sk-in-array-node-1234' }] },
      'plain-string',
      42,
      null,
    ],
    at: new Date('2026-11-24T10:00:00.000Z'),
    err: Object.assign(new Error('失败原因 Bearer leaked-in-message'), { code: 'boom' }),
    cyclic,
  }

  const out = redactForLog(input)
  const json = JSON.stringify(out)

  assert.ok(!json.includes('a=1'), '数组里的 cookie 也要遮盖')
  assert.ok(!json.includes('sk-in-array-node-1234'), '数组里的 apiKey 也要遮盖')
  assert.ok(!json.includes('cyclic-token-value'))
  assert.ok(!json.includes('leaked-in-message'), 'Error.message 里的 Bearer 值也要遮盖')
  assert.equal(out.at, '2026-11-24T10:00:00.000Z', 'Date 转 ISO 串')
  assert.match(json, /\[Circular\]/, '循环引用要变成可序列化占位符')
  assert.ok(json.includes('plain-string'))
})

test('7. 脱敏不就地修改入参：原对象仍持有原值', () => {
  const input = makeSensitiveFixture()
  const snapshot = JSON.stringify(input)

  redactForLog(input)
  redactForResponse(input)

  assert.equal(JSON.stringify(input), snapshot, '入参在两次脱敏后必须与调用前完全一致')
  assert.equal(input.headers.Authorization, 'Bearer sk-live-TOPSECRET-bearer-value')
  assert.equal(input.body.apiKey, 'sk-xxx-FAKE-KEY-123456')
  assert.equal(input.body.level1.level2.level3.token, 'deep-nested-token-value')

  // 返回的必须是新对象
  const out = redactForLog(input)
  assert.notEqual(out, input)
  assert.notEqual(out.body, input.body, '嵌套对象也不能是同一个引用')
})

test('7b. 键名大小写与分隔符不敏感（Set-Cookie / set_cookie / setCookie 同一处理）', () => {
  const variants = {
    'Set-Cookie': 'k1=v1',
    set_cookie: 'k2=v2',
    setCookie: 'k3=v3',
    AUTHORIZATION: 'Bearer v4-secret',
    api_key: 'v5-secret',
  }
  const json = JSON.stringify(redactForResponse(variants))
  for (const v of ['v1', 'v2', 'v3', 'v4-secret', 'v5-secret']) {
    assert.ok(!json.includes(v), `变体键名 ${v} 未被脱敏`)
  }
})

/* ============================================================
 * 八、方法限制 + schema 校验
 * ============================================================ */

const UPSTREAM_SCHEMA = {
  fields: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64 },
    port: { type: 'integer', required: true, min: 1, max: 65535 },
    enabled: { type: 'boolean' },
    routingMode: { type: 'string', enum: ['auto', 'direct'] },
    tags: { type: 'array', items: 'string' },
  },
}

test('8. 方法限制：只接受 GET / POST / PATCH / DELETE', () => {
  assert.deepEqual([...ADMIN_METHODS], ['GET', 'POST', 'PATCH', 'DELETE'])

  for (const method of ['PUT', 'OPTIONS', 'HEAD', 'TRACE', '']) {
    const r = validateAdminRequest(method, {}, UPSTREAM_SCHEMA)
    assert.equal(r.ok, false)
    assert.equal(r.errors[0].code, 'method_not_allowed')
  }

  // GET / DELETE 带非空请求体视为搞错端点
  const withBody = validateAdminRequest('GET', { name: 'x' }, UPSTREAM_SCHEMA)
  assert.equal(withBody.ok, false)
  assert.equal(withBody.errors[0].code, 'body_not_allowed')

  // 空对象 / undefined 不算「带体」
  assert.equal(validateAdminRequest('DELETE', {}, UPSTREAM_SCHEMA).ok, true)
  assert.equal(validateAdminRequest('DELETE', undefined, UPSTREAM_SCHEMA).ok, true)
})

test('8b. 未知字段：拒绝而不是静默忽略', () => {
  const r = validateAdminRequest('POST', { name: 'a', port: 443, typoField: 1 }, UPSTREAM_SCHEMA)
  assert.equal(r.ok, false)
  const err = r.errors.find((e) => e.code === 'unknown_field')
  assert.ok(err, '必须报 unknown_field')
  assert.equal(err.path, '#/typoField')

  // 显式 allowUnknown 时才放过（用来表达「这条端点接受扩展字段」的少数场景）
  const lenient = validateAdminRequest('POST', { name: 'a', port: 443, extra: 1 }, {
    fields: UPSTREAM_SCHEMA.fields,
    allowUnknown: true,
  })
  assert.equal(lenient.ok, true)
})

test('8c. 缺必填字段：拒绝，且一次报全', () => {
  const r = validateAdminRequest('POST', { enabled: true }, UPSTREAM_SCHEMA)
  assert.equal(r.ok, false)
  const missing = r.errors.filter((e) => e.code === 'missing_required').map((e) => e.path).sort()
  assert.deepEqual(missing, ['#/name', '#/port'], '两个必填字段要一起报出来')
})

test('8d. 类型 / 取值 / 范围不符：拒绝', () => {
  const typeErr = validateAdminRequest('POST', { name: 'a', port: '443' }, UPSTREAM_SCHEMA)
  assert.equal(typeErr.ok, false)
  assert.equal(typeErr.errors[0].code, 'type_mismatch')

  const enumErr = validateAdminRequest('POST', { name: 'a', port: 443, routingMode: 'turbo' }, UPSTREAM_SCHEMA)
  assert.equal(enumErr.ok, false)
  assert.equal(enumErr.errors[0].code, 'not_in_enum')

  const rangeErr = validateAdminRequest('POST', { name: 'a', port: 70000 }, UPSTREAM_SCHEMA)
  assert.equal(rangeErr.ok, false)
  assert.equal(rangeErr.errors[0].code, 'out_of_range')

  const itemErr = validateAdminRequest('POST', { name: 'a', port: 443, tags: ['ok', 42] }, UPSTREAM_SCHEMA)
  assert.equal(itemErr.ok, false)
  assert.equal(itemErr.errors[0].path, '#/tags/1')

  const nullErr = validateAdminRequest('POST', { name: null, port: 443 }, UPSTREAM_SCHEMA)
  assert.equal(nullErr.ok, false)
  assert.equal(nullErr.errors[0].code, 'type_mismatch', 'null 不等于「未提供」')

  // 全部合法
  const good = validateAdminRequest('PATCH', { name: 'a', port: 443, routingMode: 'direct', tags: ['x'] }, UPSTREAM_SCHEMA)
  assert.deepEqual(good, { ok: true, errors: [] })
})

/* ============================================================
 * 九、分页
 * ============================================================ */

test('9. paginate 边界：limit 钳制、offset 越界、默认值、nextOffset', () => {
  const list = Array.from({ length: 25 }, (_, i) => i)

  // 默认 limit
  const dflt = paginate(list, {})
  assert.equal(dflt.limit, PAGINATION.defaultLimit)
  assert.equal(dflt.items.length, 20)
  assert.equal(dflt.hasMore, true)
  assert.equal(dflt.nextOffset, 20)

  // limit 超上限 → 钳到 maxLimit，而不是报错
  const big = paginate(list, { limit: 1000 })
  assert.equal(big.limit, PAGINATION.maxLimit)
  assert.equal(big.items.length, 25)
  assert.equal(big.hasMore, false)
  assert.equal(big.nextOffset, null)

  // limit <= 0 → 钳到 1（不给 0 任何特殊语义）
  assert.equal(paginate(list, { limit: 0 }).limit, 1)
  assert.equal(paginate(list, { limit: -5 }).limit, 1)

  // offset 越界 → 空页 + 终态
  const over = paginate(list, { limit: 10, offset: 999 })
  assert.deepEqual(over.items, [])
  assert.equal(over.total, 25)
  assert.equal(over.hasMore, false)
  assert.equal(over.nextOffset, null)

  // offset 负数 → 钳到 0
  assert.equal(paginate(list, { offset: -10 }).offset, 0)

  // 最后一页恰好取完
  const last = paginate(list, { limit: 5, offset: 20 })
  assert.deepEqual(last.items, [20, 21, 22, 23, 24])
  assert.equal(last.hasMore, false)

  // 非数字参数走默认值，不抛
  assert.equal(paginate(list, { limit: 'abc', offset: 'xyz' }).limit, PAGINATION.defaultLimit)

  // 非数组是调用方编程错误
  assert.throws(() => paginate(/** @type {any} */ (null)), TypeError)
})

/* ============================================================
 * 十、版本冲突
 * ============================================================ */

test('10. checkVersion：一致为 true，冲突/缺版本为 false', () => {
  assert.equal(checkVersion(3, 3), true)
  assert.equal(checkVersion(3, '3'), true, '数字与字符串同值应算一致')
  assert.equal(checkVersion('"v3"', '"v3"'), true, 'ETag 形态要能比')

  assert.equal(checkVersion(3, 4), false)
  assert.equal(checkVersion('v3', 'v4'), false)

  // 缺 expected = 客户端没做乐观锁，必须拒绝（否则后写覆盖前写）
  assert.equal(checkVersion(3, undefined), false)
  assert.equal(checkVersion(3, null), false)
  assert.equal(checkVersion(3, ''), false)

  // 服务端没有当前版本时也不能声称「一致」
  assert.equal(checkVersion(undefined, 3), false)
  assert.equal(checkVersion(null, 3), false)
})

/* ============================================================
 * 十一、删除引用检查
 * ============================================================ */

test('11. assertNotReferenced：被引用时抛 409，未被引用时通过', () => {
  const groups = [
    { id: 'g1', name: 'default', upstreamIds: ['u1', 'u2'] },
    { id: 'g2', name: 'backup', upstreamIds: ['u3'] },
    { id: 'g3', name: 'empty', upstreamIds: [] },
    null,
    'not-a-group',
  ]

  // 未被引用的上游可以删
  assert.equal(assertNotReferenced('u3', []), true)
  assert.equal(assertNotReferenced('u9', groups), true)

  // 被引用时抛 TargetDenied，details 里带引用了它的分组
  assert.throws(
    () => assertNotReferenced('u1', groups),
    (err) => {
      assert.equal(err.code, 'target_denied')
      assert.equal(err.name, 'TargetDenied')
      assert.equal(err.details.status, 409)
      assert.equal(err.details.upstreamId, 'u1')
      assert.deepEqual(err.details.referencedBy.map((g) => g.id), ['g1'])
      assert.equal(err.details.referencedBy[0].name, 'default')
      // 错误信息不得含 Token 之类（这条路径本来也拿不到，作为回归断言保留）
      assert.ok(!JSON.stringify(err).includes(TOKEN))
      return true
    },
  )

  // 参数不合法是编程错误
  assert.throws(() => assertNotReferenced('', groups), TypeError)
})

/* ============================================================
 * 十二、审计日志
 * ============================================================ */

test('12. 审计记录可序列化、不含敏感值、时间可解释', () => {
  const at = 1_764_000_000_000
  const entry = makeAuditEntry({
    adminId: 'ops',
    action: 'upstream.delete',
    at,
    target: {
      id: 'u1',
      apiKey: 'sk-live-AUDIT-SHOULD-NOT-LEAK',
      headers: { authorization: 'Bearer audit-bearer-should-not-leak' },
      nested: { deep: { password: 'audit-password-should-not-leak' } },
    },
    result: { status: 200, note: 'deleted', cookie: 'sid=audit-cookie-should-not-leak' },
  })

  const json = JSON.stringify(entry)
  for (const fragment of [
    'sk-live-AUDIT-SHOULD-NOT-LEAK',
    'audit-bearer-should-not-leak',
    'audit-password-should-not-leak',
    'audit-cookie-should-not-leak',
  ]) {
    assert.ok(!json.includes(fragment), `审计记录泄露了：${fragment}`)
  }

  assert.equal(entry.at, new Date(at).toISOString(), '时间用 ISO 串，跨日志系统不用猜时区')
  assert.equal(entry.adminId, 'ops')
  assert.equal(entry.action, 'upstream.delete')
  assert.equal(entry.target.id, 'u1', '非敏感字段要保留')
  assert.equal(entry.result.note, 'deleted')
  assert.ok(json.includes('[REDACTED]'))

  // 字段顺序稳定，便于日志对拍
  assert.deepEqual(Object.keys(entry), ['at', 'adminId', 'action', 'target', 'result'])
})

test('12b. 审计记录不允许匿名、不允许无动作', () => {
  assert.throws(() => makeAuditEntry({ action: 'x' }), TypeError)
  assert.throws(() => makeAuditEntry({ adminId: '  ', action: 'x' }), TypeError)
  assert.throws(() => makeAuditEntry({ adminId: 'ops' }), TypeError)

  // adminId 长得像凭据时也要被遮住（防「拿 Token 当 id 传」）
  const entry = makeAuditEntry({
    adminId: 'sk-live-ADMINID-AS-TOKEN-9999',
    action: 'upstream.create',
  })
  assert.ok(!JSON.stringify(entry).includes('sk-live-ADMINID-AS-TOKEN-9999'))
})

test('12c. 审计与授权串起来：被拒的请求也能记一条不含敏感值的记录', () => {
  const guard = createAdminGuard({ token: TOKEN })
  const req = makeReq({ headers: { authorization: 'Bearer wrong-token-that-should-not-leak' } })

  assertDenied(() => guard.authorize(req), 401)

  const entry = makeAuditEntry({
    adminId: 'anonymous',
    action: 'admin.auth',
    target: { route: req.route, headers: req.headers },
    result: { status: 401, reason: 'unauthorized' },
  })

  const json = JSON.stringify(entry)
  assert.ok(!json.includes('wrong-token-that-should-not-leak'))
  assert.ok(!json.includes(TOKEN))
  assert.equal(entry.result.status, 401)
})
