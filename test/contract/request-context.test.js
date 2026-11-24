/**
 * contract-request-context.test.js — 统一请求上下文（Issue #26 / A2）
 *
 * 两条设计决定各有专门的用例守着：
 *   · clientId / routeGroupId 不允许为空（防止「半认证」状态）
 *   · 返回对象必须 frozen（防止某阶段就地篡改、下游看到被污染的输入）
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  makeRequestContext, isRequestContext, REQUEST_MODES,
} from '../../lib/contract/request-context.mjs'

/** 一份最小合法输入 */
function base(over = {}) {
  return {
    clientId: 'client-a',
    routeGroupId: 'group-1',
    mode: 'forward',
    method: 'GET',
    originalUrl: 'http://example.com/x',
    ...over,
  }
}

/* ============================================================
 * 正常构造
 * ============================================================ */

test('最小输入能构造，且补齐默认值', () => {
  const before = Date.now()
  const c = makeRequestContext(base())

  assert.equal(c.clientId, 'client-a')
  assert.equal(c.routeGroupId, 'group-1')
  assert.equal(c.mode, 'forward')
  assert.equal(c.method, 'GET')
  assert.equal(c.originalUrl, 'http://example.com/x')

  assert.equal(typeof c.requestId, 'string')
  assert.ok(c.requestId.length >= 32, 'requestId 应是 UUID 级别的长度')
  assert.equal(c.body, null, '未提供 body 时为 null')
  assert.ok(c.signal && typeof c.signal.aborted === 'boolean', '应自动建 signal')
  assert.ok(c.startedAt >= before && c.startedAt <= Date.now())
})

test('两次构造的 requestId 不同', () => {
  const a = makeRequestContext(base())
  const b = makeRequestContext(base())
  assert.notEqual(a.requestId, b.requestId)
})

test('method 自动转大写并去空白', () => {
  assert.equal(makeRequestContext(base({ method: ' post ' })).method, 'POST')
  assert.equal(makeRequestContext(base({ method: 'patch' })).method, 'PATCH')
})

test('headers 键被规范化为小写，值原样保留', () => {
  const c = makeRequestContext(base({
    headers: {
      'Content-Type': 'application/json',
      'X-Request-Id': 'abc',
      'AUTHORIZATION': 'Bearer xyz',
    },
  }))
  assert.deepEqual(c.headers, {
    'content-type': 'application/json',
    'x-request-id': 'abc',
    authorization: 'Bearer xyz',
  }, '值里的空格与大小写必须原样保留（可能是签名的一部分）')
})

test('headers 数组值原样保留', () => {
  const c = makeRequestContext(base({ headers: { 'x-multi': ['a', 'b'] } }))
  assert.deepEqual(c.headers['x-multi'], ['a', 'b'])
})

test('空键名的 header 被跳过', () => {
  const c = makeRequestContext(base({ headers: { '': 'x', 'a': '1' } }))
  assert.deepEqual(c.headers, { a: '1' })
})

test('未提供 headers 时为空对象', () => {
  assert.deepEqual(makeRequestContext(base()).headers, {})
})

test('传入的 signal 原样使用（不是新建的）', () => {
  const ac = new AbortController()
  const c = makeRequestContext(base({ signal: ac.signal }))
  assert.equal(c.signal, ac.signal)
  ac.abort()
  assert.equal(c.signal.aborted, true, '外部取消必须反映到 context')
})

/* ============================================================
 * 身份字段：不允许空值（核心设计决定）
 * ============================================================ */

test('clientId 为空字符串时抛 TypeError', () => {
  assert.throws(() => makeRequestContext(base({ clientId: '' })), {
    name: 'TypeError',
    message: /clientId/,
  })
})

test('routeGroupId 为空字符串时抛 TypeError', () => {
  assert.throws(() => makeRequestContext(base({ routeGroupId: '' })), {
    name: 'TypeError',
    message: /routeGroupId/,
  })
})

test('身份字段缺失或非字符串时抛 TypeError', () => {
  for (const bad of [undefined, null, 0, {}, []]) {
    assert.throws(() => makeRequestContext(base({ clientId: bad })), TypeError, `clientId=${bad}`)
    assert.throws(() => makeRequestContext(base({ routeGroupId: bad })), TypeError, `routeGroupId=${bad}`)
  }
})

test('错误信息说明「空值应在调用前拒绝」', () => {
  try {
    makeRequestContext(base({ clientId: '' }))
    assert.fail('应该抛错')
  } catch (e) {
    assert.match(e.message, /认证/, '应提示这是认证结果，不是请求输入')
  }
})

/* ============================================================
 * mode 与其它必填字段
 * ============================================================ */

test('mode 只接受 forward / reverse', () => {
  assert.equal(makeRequestContext(base({ mode: 'reverse' })).mode, 'reverse')
  for (const bad of ['Forward', 'proxy', '', null, undefined, 1]) {
    assert.throws(() => makeRequestContext(base({ mode: bad })), TypeError, `mode=${bad}`)
  }
})

test('REQUEST_MODES 与实际接受值一致', () => {
  assert.deepEqual([...REQUEST_MODES], ['forward', 'reverse'])
})

test('method / originalUrl 不接受空值', () => {
  assert.throws(() => makeRequestContext(base({ method: '' })), TypeError)
  assert.throws(() => makeRequestContext(base({ method: '   ' })), TypeError)
  assert.throws(() => makeRequestContext(base({ originalUrl: '' })), TypeError)
})

test('非对象参数抛 TypeError', () => {
  for (const bad of [null, undefined, 'x', 42, []]) {
    assert.throws(() => makeRequestContext(bad), TypeError)
  }
})

test('signal 不是 AbortSignal 时抛 TypeError', () => {
  assert.throws(() => makeRequestContext(base({ signal: {} })), TypeError)
  assert.throws(() => makeRequestContext(base({ signal: 'x' })), TypeError)
})

test('startedAt 非有限数字时抛 TypeError', () => {
  for (const bad of [NaN, Infinity, '123']) {
    assert.throws(() => makeRequestContext(base({ startedAt: bad })), TypeError, `startedAt=${bad}`)
  }
})

/* ============================================================
 * frozen：阻止就地篡改
 * ============================================================ */

test('返回对象是 frozen 的，改字段不生效', () => {
  const c = makeRequestContext(base())
  assert.equal(Object.isFrozen(c), true)

  // 严格模式下赋值会抛错，非严格模式静默失败 —— 两种都不该改变值
  try { c.clientId = 'attacker' } catch { /* strict mode */ }
  assert.equal(c.clientId, 'client-a', '篡改不能生效')
})

test('headers 对象本身未被 freeze（值仍可读，但属性改动会影响 context）', () => {
  // 这是刻意的：headers 里的数组值需要能被迭代，深 freeze 成本高且收益低。
  // 记录下这个边界，避免误以为整个结构都不可变。
  const c = makeRequestContext(base({ headers: { a: '1' } }))
  assert.equal(Object.isFrozen(c.headers), false,
    '浅 freeze：顶层属性不可改，但 headers 内部未冻结')
})

/* ============================================================
 * isRequestContext
 * ============================================================ */

test('isRequestContext 识别合法对象', () => {
  assert.equal(isRequestContext(makeRequestContext(base())), true)
})

test('isRequestContext 拒绝各种不合法的值', () => {
  const good = makeRequestContext(base())
  const cases = [
    null, undefined, 'x', 42,
    {},
    { ...good, clientId: '' },
    { ...good, mode: 'nope' },
    { ...good, headers: null },
    { ...good, startedAt: 'x' },
    { ...good, signal: null },
  ]
  for (const c of cases) {
    assert.equal(isRequestContext(c), false, JSON.stringify(c)?.slice(0, 60))
  }
})

test('isRequestContext 对「看似合法但缺字段」的对象返回 false', () => {
  const good = makeRequestContext(base())
  for (const k of ['requestId', 'clientId', 'routeGroupId', 'method', 'originalUrl']) {
    const copy = { ...good }
    delete copy[k]
    assert.equal(isRequestContext(copy), false, `缺 ${k} 应被拒`)
  }
})

/* ============================================================
 * 两种入口的等价性（契约核心）
 * ============================================================ */

test('forward 与 reverse 产出除 mode 外完全相同的结构', () => {
  const input = {
    requestId: 'fixed-id',
    clientId: 'c1',
    routeGroupId: 'g1',
    method: 'POST',
    originalUrl: 'https://api.example.com/v1/x',
    headers: { 'Content-Type': 'application/json' },
    startedAt: 1_700_000_000_000,
  }
  const f = makeRequestContext({ ...input, mode: 'forward' })
  const r = makeRequestContext({ ...input, mode: 'reverse' })

  assert.deepEqual(Object.keys(f).sort(), Object.keys(r).sort(), '字段集合必须一致')

  for (const k of Object.keys(f)) {
    if (k === 'mode') continue
    assert.deepEqual(f[k], r[k], `字段 ${k} 必须一致`)
  }
  assert.equal(f.mode, 'forward')
  assert.equal(r.mode, 'reverse')
})
