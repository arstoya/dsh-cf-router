/**
 * target-validator.test.js — B1 目标验证（v0.4.0）
 *
 * 九类必测项各自成组，另加规范化 / pin / URL 级 / authority 解析四组：
 *   1 回环（IPv4、IPv6、IPv4-mapped IPv6）
 *   2 RFC1918
 *   3 IPv6 ULA
 *   4 link-local
 *   5 云元数据（含 IPv6 变体）
 *   6 CGNAT
 *   7 混合 A/AAAA（一条不合规整条拒绝）
 *   8 重定向到内网
 *   9 非白名单端口 / host
 *
 * 硬约束：本文件**不允许产生真实 DNS 查询**。所有域名用例都通过
 * `options.resolve` 注入假解析器；IP 字面量在实现里本就不查 DNS，
 * 所以整套测试离线可跑。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { domainToASCII } from 'node:url'

import {
  validateAuthority,
  validateTargetUrl,
  isRedirectAllowed,
  parseAuthorityTarget,
  classifyAddress,
} from '../../lib/target-validator.mjs'
import { TargetDenied } from '../../lib/contract/errors.mjs'

const PUBLIC_V4 = '93.184.216.34'
const PUBLIC_V6 = '2606:4700:4700::1111'

/**
 * 白名单只放这里列出的 host。没列出来的一律走「非白名单」用例 ——
 * 白名单是精确匹配，多写一条就等于多测掉一个漏判。
 */
const ALLOW = [
  'api.example.com', 'secure.example.com', 'cdn.example.com',
  'mixed.example.com', 'badns.example.com', 'localhost',
  '127.0.0.1', '127.255.255.254',
  '10.0.0.1', '172.16.5.5', '172.31.255.254', '192.168.1.1',
  '169.254.1.1', '169.254.169.254', '100.100.100.200',
  '192.0.0.192', '168.63.129.16',
  '100.64.0.1', '100.127.255.254', '100.128.0.1',
  '203.0.113.5', '93.184.216.34', '8.8.8.8', '1.1.1.1',
  '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1',
  'fd00:ec2::254', 'fe80::a9fe:a9fe',
  '::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:8.8.8.8', '::ffff:10.0.0.1',
  '::7f00:1',
  '2606:4700:4700::1111',
]

const allowlist = new Set(ALLOW)

/**
 * 假解析器：只认 map 里写死的名字，其余抛 ENOTFOUND。
 * `fn.calls` 记录调用过的主机名，用来断言「只解析一次」。
 *
 * @param {Record<string, string|string[]>} map
 */
function fakeResolve(map) {
  /** @type {string[]} */
  const calls = []
  const fn = async (host) => {
    calls.push(host)
    if (!Object.prototype.hasOwnProperty.call(map, host)) {
      const err = new Error(`ENOTFOUND ${host}`)
      err.code = 'ENOTFOUND'
      throw err
    }
    const value = map[host]
    return Array.isArray(value) ? value : [value]
  }
  fn.calls = calls
  return fn
}

const EMPTY_RESOLVE = () => fakeResolve({})

/**
 * @param {Record<string, unknown>} [extra]
 */
function opts(extra = {}) {
  return { allowlist, resolve: EMPTY_RESOLVE(), ...extra }
}

/**
 * 断言调用被 TargetDenied 拒绝，并核对 reason / host 与 details 的形状。
 *
 * 这里顺带把契约层那条硬约束测了：details 只能有 host 与 reason，
 * 且序列化后不得出现 token / cookie / authorization 之类敏感字段名。
 *
 * @param {() => Promise<unknown>} fn
 * @param {string} reason
 * @param {string} [host]
 */
async function expectDenied(fn, reason, host) {
  await assert.rejects(fn, (err) => {
    assert.ok(err instanceof TargetDenied, `应抛 TargetDenied，实际 ${err && err.name}`)
    assert.equal(err.code, 'target_denied')
    assert.equal(err.details.reason, reason, '拒绝原因')
    if (host !== undefined) assert.equal(err.details.host, host, 'details.host')
    assert.deepEqual(Object.keys(err.details).sort(), ['host', 'reason'], 'details 只允许 host 与 reason')
    assert.ok(
      !/token|cookie|authorization|password/i.test(JSON.stringify(err)),
      'details 不得含敏感字段',
    )
    return true
  })
}

/* ============================================================
 * 1. 回环
 * ============================================================ */

test('回环：IPv4、IPv6、IPv4-mapped IPv6 一律拒绝', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('127.0.0.1', 443, o), 'loopback', '127.0.0.1')
  await expectDenied(() => validateAuthority('127.255.255.254', 443, o), 'loopback', '127.255.255.254')
  // IPv6 字面量两种写法都要认：带方括号（authority 形式）与裸形式
  await expectDenied(() => validateAuthority('[::1]', 443, o), 'loopback', '::1')
  await expectDenied(() => validateAuthority('0:0:0:0:0:0:0:1', 443, o), 'loopback', '::1')
  // 这一条是 ssrf-guard 只做 IPv4 时漏掉的整类绕过
  await expectDenied(
    () => validateAuthority('[::ffff:127.0.0.1]', 443, o),
    'ipv4_mapped_loopback',
    '::ffff:7f00:1',
  )
  // 已废弃的 IPv4-compatible 写法同样要拆开判
  await expectDenied(() => validateAuthority('::7f00:1', 443, o), 'ipv4_compatible_loopback', '::7f00:1')
})

test('回环：域名解析到 127.0.0.1 也拒绝', async () => {
  const o = opts({ resolve: fakeResolve({ 'api.example.com': '127.0.0.1' }) })
  await expectDenied(() => validateAuthority('api.example.com', 443, o), 'loopback', 'api.example.com')
})

/* ============================================================
 * 2. RFC1918
 * ============================================================ */

test('RFC1918：10/8、172.16/12、192.168/16 全部拒绝', async () => {
  const o = opts()
  const cases = [
    ['10.0.0.1', 'private_10'],
    ['172.16.5.5', 'private_172'],
    ['172.31.255.254', 'private_172'],
    ['192.168.1.1', 'private_192'],
  ]
  for (const [ip, reason] of cases) {
    await expectDenied(() => validateAuthority(ip, 443, o), reason, ip)
  }
})

test('RFC1918 边界：172.15 / 172.32 属公网，不应被私网规则命中', async () => {
  assert.equal(classifyAddress('172.15.0.1').reason, null)
  assert.equal(classifyAddress('172.32.0.1').reason, null)
})

/* ============================================================
 * 3. IPv6 ULA
 * ============================================================ */

test('IPv6 ULA（fc00::/7）拒绝', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('fc00::1', 443, o), 'unique_local', 'fc00::1')
  await expectDenied(() => validateAuthority('fd12:3456::1', 443, o), 'unique_local', 'fd12:3456::1')
})

/* ============================================================
 * 4. link-local
 * ============================================================ */

test('link-local：169.254/16 与 fe80::/10 拒绝', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('169.254.1.1', 443, o), 'link_local', '169.254.1.1')
  await expectDenied(() => validateAuthority('[fe80::1]', 443, o), 'link_local', 'fe80::1')
  await expectDenied(() => validateAuthority('fec0::1', 443, { ...o, allowlist: new Set([...ALLOW, 'fec0::1']) }), 'site_local', 'fec0::1')
})

/* ============================================================
 * 5. 云元数据
 * ============================================================ */

test('云元数据：IPv4 端点全部按 metadata 拒绝（不是 link_local）', async () => {
  const o = opts()
  for (const ip of ['169.254.169.254', '100.100.100.200', '192.0.0.192', '168.63.129.16']) {
    await expectDenied(() => validateAuthority(ip, 443, o), 'metadata', ip)
  }
})

test('云元数据：IPv6 变体与其 IPv4-mapped 形式同样拒绝', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('fd00:ec2::254', 443, o), 'metadata', 'fd00:ec2::254')
  // fe80::a9fe:a9fe 就是 169.254.169.254 的十六进制同址写法
  await expectDenied(() => validateAuthority('fe80::a9fe:a9fe', 443, o), 'metadata', 'fe80::a9fe:a9fe')
  await expectDenied(
    () => validateAuthority('[::ffff:169.254.169.254]', 443, o),
    'ipv4_mapped_metadata',
    '::ffff:a9fe:a9fe',
  )
})

test('云元数据：allowPrivate 打开也不放行', async () => {
  const o = opts({ allowPrivate: true })
  await expectDenied(() => validateAuthority('169.254.169.254', 443, o), 'metadata')
  await expectDenied(() => validateAuthority('fd00:ec2::254', 443, o), 'metadata')
  await expectDenied(() => validateAuthority('[::ffff:169.254.169.254]', 443, o), 'ipv4_mapped_metadata')
})

/* ============================================================
 * 6. CGNAT
 * ============================================================ */

test('CGNAT：100.64/10 拒绝，100.128/10 是公网', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('100.64.0.1', 443, o), 'cgnat', '100.64.0.1')
  await expectDenied(() => validateAuthority('100.127.255.254', 443, o), 'cgnat', '100.127.255.254')

  const r = await validateAuthority('100.128.0.1', 443, o)
  assert.deepEqual(r.addresses, ['100.128.0.1'])
})

/* ============================================================
 * 7. 混合 A/AAAA
 * ============================================================ */

test('混合 A/AAAA：一条不合规就整条拒绝，不挑安全的用', async () => {
  const v4v4 = opts({ resolve: fakeResolve({ 'mixed.example.com': [PUBLIC_V4, '127.0.0.1'] }) })
  await expectDenied(
    () => validateAuthority('mixed.example.com', 443, v4v4),
    'mixed_unsafe_address',
    'mixed.example.com',
  )

  const v6v6 = opts({
    resolve: fakeResolve({ 'mixed.example.com': [PUBLIC_V6, 'fd12:3456::1'] }),
  })
  await expectDenied(
    () => validateAuthority('mixed.example.com', 443, v6v6),
    'mixed_unsafe_address',
    'mixed.example.com',
  )
})

test('混合结果全部合规 → 通过，addresses 保持解析顺序', async () => {
  const o = opts({ resolve: fakeResolve({ 'mixed.example.com': [PUBLIC_V4, PUBLIC_V6] }) })
  const r = await validateAuthority('mixed.example.com', 443, o)
  assert.deepEqual(r.addresses, [PUBLIC_V4, PUBLIC_V6])
  assert.equal(r.pinned, PUBLIC_V4)
})

test('全部不合规时上报第一条的具体分类，而不是宽泛的 mixed', async () => {
  const o = opts({ resolve: fakeResolve({ 'api.example.com': ['10.0.0.1', '127.0.0.1'] }) })
  await expectDenied(() => validateAuthority('api.example.com', 443, o), 'private_10', 'api.example.com')
})

/* ============================================================
 * 8. 重定向
 * ============================================================ */

test('重定向：同 host 同 scheme 允许，跳内网/非白名单一律 false', async () => {
  const o = opts({
    resolve: fakeResolve({
      'api.example.com': PUBLIC_V4,
      'secure.example.com': PUBLIC_V6,
    }),
  })
  const from = 'https://api.example.com/v1/a'

  assert.equal(await isRedirectAllowed(from, 'https://api.example.com/v1/b', o), true)

  // 内网 / 元数据 / 非白名单 / 非 http(s) 全部 false
  assert.equal(await isRedirectAllowed(from, 'http://10.0.0.1/admin', o), false)
  assert.equal(await isRedirectAllowed(from, 'http://169.254.169.254/latest/meta-data/', o), false)
  assert.equal(await isRedirectAllowed(from, 'https://evil.example.net/', o), false)
  assert.equal(await isRedirectAllowed(from, 'file:///etc/passwd', o), false)
  assert.equal(await isRedirectAllowed(from, 'http://[::1]:80/', o), false)
  // 畸形 Location 也不能抛出去（返回 false，不是异常）
  assert.equal(await isRedirectAllowed(from, 'not-a-url', o), false)
})

test('重定向：https→http 默认禁止，显式放开才允许', async () => {
  const o = opts({ resolve: fakeResolve({ 'api.example.com': PUBLIC_V4 }) })
  const from = 'https://api.example.com/a'
  const to = 'http://api.example.com/b'

  assert.equal(await isRedirectAllowed(from, to, o), false)
  assert.equal(await isRedirectAllowed(from, to, { ...o, allowSchemeDowngrade: true }), true)
})

test('重定向：跨 host 默认允许，收紧后只允许同 host', async () => {
  const o = opts({
    resolve: fakeResolve({ 'api.example.com': PUBLIC_V4, 'secure.example.com': PUBLIC_V6 }),
  })
  const from = 'https://api.example.com/a'
  const to = 'https://secure.example.com/b'

  assert.equal(await isRedirectAllowed(from, to, o), true)
  assert.equal(await isRedirectAllowed(from, to, { ...o, allowCrossHostRedirect: false }), false)
})

/* ============================================================
 * 9. 非白名单端口 / host
 * ============================================================ */

test('端口白名单：默认只放 80/443，其余拒绝；显式配置后放行', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('api.example.com', 8443, o), 'port_not_allowed', 'api.example.com')
  await expectDenied(() => validateAuthority('api.example.com', 22, o), 'port_not_allowed', 'api.example.com')

  const relaxed = {
    ...o,
    allowedPorts: [443, 8443],
    resolve: fakeResolve({ 'api.example.com': PUBLIC_V4 }),
  }
  const r = await validateAuthority('api.example.com', 8443, relaxed)
  assert.equal(r.port, 8443)
})

test('端口白名单：空集合等于全关，非法端口直接 bad_port', async () => {
  const o = opts({ allowedPorts: [] })
  await expectDenied(() => validateAuthority('api.example.com', 443, o), 'port_not_allowed')

  await expectDenied(() => validateAuthority('api.example.com', 0, opts()), 'bad_port')
  await expectDenied(() => validateAuthority('api.example.com', 65536, opts()), 'bad_port')
  await expectDenied(() => validateAuthority('api.example.com', '80x', opts()), 'bad_port')
  await expectDenied(() => validateAuthority('api.example.com', null, opts()), 'missing_port')
})

test('host 白名单：精确匹配，后缀与子域都不算命中', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('example.com', 443, o), 'not_allowlisted', 'example.com')
  await expectDenied(
    () => validateAuthority('evil-example.com', 443, o),
    'not_allowlisted',
    'evil-example.com',
  )
  await expectDenied(
    () => validateAuthority('api.example.com.evil.tld', 443, o),
    'not_allowlisted',
    'api.example.com.evil.tld',
  )
  await expectDenied(() => validateAuthority('www.example.com', 443, o), 'not_allowlisted')
})

test('host 白名单：IP 字面量也必须写进白名单', async () => {
  const o = opts()
  // 公网地址但未列入白名单 —— 否则这个代理就成了开放正向代理
  await expectDenied(() => validateAuthority('104.16.0.1', 443, o), 'not_allowlisted', '104.16.0.1')
})

test('层级分离：authority 级拒绝 URL 形态的输入', async () => {
  const o = opts()
  await expectDenied(() => validateAuthority('https://api.example.com', 443, o), 'has_scheme')
  await expectDenied(() => validateAuthority('api.example.com/v1', 443, o), 'has_path_or_query')
  await expectDenied(() => validateAuthority('user@api.example.com', 443, o), 'has_userinfo')
  await expectDenied(() => validateAuthority('api.example.com:443', 443, o), 'host_has_port')
})

/* ============================================================
 * 规范化
 * ============================================================ */

test('规范化：大小写、末尾点归一到同一条目', async () => {
  const o = opts({ resolve: fakeResolve({ 'api.example.com': PUBLIC_V4 }) })
  for (const input of ['api.example.com', 'API.Example.COM', 'api.example.com.']) {
    const r = await validateAuthority(input, 443, o)
    assert.equal(r.host, 'api.example.com', `${input} 应规范化成小写去尾点`)
  }
})

test('规范化：国际化域名转 punycode 后才能命中白名单', async () => {
  const idn = '中文.example'
  const ascii = domainToASCII(idn)
  assert.ok(ascii.startsWith('xn--'), 'punycode 前缀')

  const o = opts({ allowlist: [idn, 'api.example.com'], resolve: fakeResolve({ [ascii]: PUBLIC_V4 }) })
  const r = await validateAuthority(idn, 443, o)
  assert.equal(r.host, ascii)
})

test('规范化：IPv6 多种写法视为同一主机（白名单只需写一条）', async () => {
  const o = opts({
    allowlist: ['2606:4700:4700::1111'],
    resolve: EMPTY_RESOLVE(),
  })
  const r = await validateAuthority('2606:4700:4700:0:0:0:0:1111', 443, o)
  assert.equal(r.host, '2606:4700:4700::1111')
})

test('规范化：十进制 / 十六进制 / 短段 IPv4 伪装一律拒绝', async () => {
  const o = opts()
  for (const [input, reason] of [
    ['2130706433', 'integer_literal'],
    ['0x7f.0.0.1', 'hex_literal'],
    ['1.2.3', 'numeric_host'],
  ]) {
    await expectDenied(() => validateAuthority(input, 443, o), reason)
  }
})

/* ============================================================
 * DNS rebinding
 * ============================================================ */

test('DNS rebinding：lookup 钉死校验过的地址，不再解析第二次', async () => {
  const resolve = fakeResolve({ 'api.example.com': PUBLIC_V4 })
  const r = await validateAuthority('api.example.com', 443, opts({ resolve }))

  const all = await new Promise((res, rej) => {
    r.lookup('evil.attacker.test', { all: true }, (e, a) => (e ? rej(e) : res(a)))
  })
  assert.deepEqual(all, [{ address: PUBLIC_V4, family: 4 }], 'all 形式返回全部已校验地址')

  const single = await new Promise((res, rej) => {
    r.lookup('evil.attacker.test', {}, (e, address, family) => (e ? rej(e) : res({ address, family })))
  })
  assert.deepEqual(single, { address: PUBLIC_V4, family: 4 }, '单地址形式返回首个已校验地址')

  // 只有校验阶段解析过一次，lookup 内部没有重新查询
  assert.deepEqual(resolve.calls, ['api.example.com'])
})

/* ============================================================
 * 解析失败 / 非法地址
 * ============================================================ */

test('解析失败一律 TargetDenied(resolve_failed)，不抛 DnsFailure', async () => {
  const o = opts() // 空 map → fakeResolve 抛 ENOTFOUND
  await expectDenied(() => validateAuthority('badns.example.com', 443, o), 'resolve_failed', 'badns.example.com')
})

test('空解析结果与非法地址都不算通过', async () => {
  await expectDenied(
    () => validateAuthority('api.example.com', 443, opts({ resolve: async () => [] })),
    'no_addresses',
    'api.example.com',
  )
  await expectDenied(
    () => validateAuthority('api.example.com', 443, opts({ resolve: async () => ['not-an-ip'] })),
    'invalid_address',
    'api.example.com',
  )
})

/* ============================================================
 * allowPrivate
 * ============================================================ */

test('allowPrivate：私网族放行，但文档段等非私网仍拒绝', async () => {
  const o = opts({ allowPrivate: true })

  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', 'fc00::1', 'fe80::1', '100.64.0.1']) {
    const r = await validateAuthority(ip, 443, o)
    assert.deepEqual(r.addresses, [classifyAddress(ip).address], `${ip} 应被放行`)
  }

  // IPv4-mapped 的私网地址：拆开判之后同样受 allowPrivate 控制
  const mapped = await validateAuthority('[::ffff:10.0.0.1]', 443, o)
  assert.deepEqual(mapped.addresses, ['::ffff:a00:1'])

  await expectDenied(() => validateAuthority('203.0.113.5', 443, o), 'documentation', '203.0.113.5')
})

/* ============================================================
 * 完整 URL 级
 * ============================================================ */

test('validateTargetUrl：返回规范化的 scheme/host/port/path/query', async () => {
  const o = opts({
    allowedPorts: [443, 8443],
    resolve: fakeResolve({ 'api.example.com': PUBLIC_V4 }),
  })

  const r = await validateTargetUrl('HTTPS://API.Example.COM:8443/v1/models?x=1&y=2', o)
  assert.equal(r.scheme, 'https')
  assert.equal(r.host, 'api.example.com')
  assert.equal(r.port, 8443)
  assert.equal(r.path, '/v1/models')
  assert.equal(r.query, '?x=1&y=2')
  assert.deepEqual(r.addresses, [PUBLIC_V4])
  assert.equal(typeof r.lookup, 'function')
})

test('validateTargetUrl：默认端口补全，空路径归一为 /', async () => {
  const o = opts({ resolve: fakeResolve({ 'api.example.com': PUBLIC_V4 }) })
  const r = await validateTargetUrl('https://api.example.com', o)
  assert.equal(r.port, 443)
  assert.equal(r.path, '/')
  assert.equal(r.query, '')
})

test('validateTargetUrl：userinfo / 非 http(s) scheme / 控制字符 / 畸形 URL 拒绝', async () => {
  const o = opts({ resolve: fakeResolve({ 'api.example.com': PUBLIC_V4 }) })

  await expectDenied(() => validateTargetUrl('http://user:pass@api.example.com/', o), 'url_has_userinfo')
  await expectDenied(() => validateTargetUrl('file:///etc/passwd', o), 'scheme_not_allowed')
  await expectDenied(() => validateTargetUrl('ftp://api.example.com/', o), 'scheme_not_allowed')
  await expectDenied(() => validateTargetUrl('http://api.example.com/\n', o), 'url_has_control_chars')
  await expectDenied(() => validateTargetUrl('http://api.example.com/a b', o), 'url_has_control_chars')
  await expectDenied(() => validateTargetUrl('', o), 'empty_url')
  await expectDenied(() => validateTargetUrl('http://', o), 'malformed_url')
})

test('validateTargetUrl：URL 形式里的映射地址同样被拆开判', async () => {
  const o = opts({ resolve: EMPTY_RESOLVE() })
  await expectDenied(() => validateTargetUrl('http://[::ffff:127.0.0.1]/', o), 'ipv4_mapped_loopback')
  await expectDenied(() => validateTargetUrl('http://[::1]/', o), 'loopback')
  await expectDenied(() => validateTargetUrl('http://169.254.169.254/', o), 'metadata')
})

/* ============================================================
 * authority-form 解析（不要用 split(':')）
 * ============================================================ */

test('parseAuthorityTarget：认得方括号 IPv6、裸 IPv6、缺端口与非法端口', () => {
  assert.deepEqual(parseAuthorityTarget('[::1]:8443'), { ok: true, host: '[::1]', port: 8443 })
  assert.deepEqual(parseAuthorityTarget('[2001:db8::1]:443'), { ok: true, host: '[2001:db8::1]', port: 443 })
  assert.deepEqual(parseAuthorityTarget('::1', 443), { ok: true, host: '::1', port: 443 })
  assert.deepEqual(parseAuthorityTarget('api.example.com:443'), { ok: true, host: 'api.example.com', port: 443 })
  assert.deepEqual(parseAuthorityTarget('api.example.com'), { ok: false, reason: 'missing_port' })
  assert.deepEqual(parseAuthorityTarget('api.example.com:0'), { ok: false, reason: 'bad_port' })
  assert.deepEqual(parseAuthorityTarget('api.example.com:99999'), { ok: false, reason: 'bad_port' })
  assert.deepEqual(parseAuthorityTarget('https://api.example.com:443'), { ok: false, reason: 'has_scheme' })
  assert.deepEqual(parseAuthorityTarget('a.com:1:2'), { ok: false, reason: 'bad_authority' })
  assert.deepEqual(parseAuthorityTarget('api.example.com:443/path'), { ok: false, reason: 'has_path_or_query' })
})

/* ============================================================
 * 分类器本身
 * ============================================================ */

test('classifyAddress：公网 IPv4/IPv6 无拒绝原因，空输入按无效处理', () => {
  assert.equal(classifyAddress('8.8.8.8').reason, null)
  assert.equal(classifyAddress('1.1.1.1').reason, null)
  assert.equal(classifyAddress(PUBLIC_V6).reason, null)
  assert.equal(classifyAddress('').reason, 'invalid_address')
  assert.equal(classifyAddress('999.1.1.1').reason, 'invalid_address')
})
