/**
 * target-validator.mjs — 唯一的目标验证入口（v0.4.0 / B1）
 *
 * 这个模块存在的理由是「同一套判断，只能有一处实现」。v0.4.0 的两种入口
 * （Forward / Reverse）与 CONNECT 隧道都必须经过这里，否则三处各写一份
 * 地址分类，迟早会出现「一处拦了、另一处漏了」。
 *
 * ## 为什么必须分成两个层级（不能只做一个）
 *
 * CONNECT 请求的 target 是 authority-form（`host:port`），握手时 TLS 还没解开，
 * **看不到路径、query、Header**。所以 CONNECT 能拿到的事实只有 host 和 port。
 * 如果让它去调「完整 URL 级」的验证函数，调用方就必须先编造一个 scheme 和 path
 * 才能过接口 —— 那是用弱输入冒充强校验，日志里会显示「完整验证已通过」，
 * 而实际上路径从未被任何人看过。这种「看似更严、实际更松」的设计比不复用更危险。
 *
 * 因此：
 *   - `validateAuthority(host, port, opts)`  ← CONNECT 用，只验 host + port
 *   - `validateTargetUrl(rawUrl, opts)`      ← Forward / Reverse 用，验 scheme + host + port + path
 *
 * 两者共享同一份地址分类与白名单逻辑（内部函数），**不共享输入契约**。
 *
 * ## 其余关键决定及其理由
 *
 * 1. **不按 `split(':')` 解析 authority。** IPv6 字面量自带多个冒号，
 *    按冒号切会把 `[::1]:443` 切成 4 段；这也是历史上各类 SSRF 绕过
 *    （`http://evil.com:80@127.0.0.1`）的入口。所以端口是**独立参数**，
 *    真要解析 `host:port` 字符串时走 `parseAuthorityTarget()`，它认得方括号。
 *
 * 2. **IPv4-mapped IPv6 必须拆开判。** `::ffff:127.0.0.1` 在 IPv6 分类表里
 *    只是一段普通地址，但内核连它时打到的是 127.0.0.1。只判 IPv4 的实现
 *    会在这里漏掉整类绕过。本模块把 `::ffff:0:0/96`（IPv4-mapped）与
 *    `::/96`（已废弃的 IPv4-compatible）里的末 32 位抽出来，**按 IPv4 重新分类**，
 *    拒绝理由带上 `ipv4_mapped_` / `ipv4_compatible_` 前缀以便定位。
 *
 * 3. **混合 A/AAAA 整条拒绝，不挑安全的那条用。** 一个域名同时解析出
 *    公网地址和回环地址，说明解析结果已被污染或配置异常。此时「挑一个安全的连」
 *    会让攻击者只花一次投毒就拿到一个 50% 的机会，而且日志上看不出异常。
 *
 * 4. **验证结果必须钉进连接（防 DNS rebinding）。** 校验与实际连接之间如果
 *    还有第二次解析，攻击者可以让两次解析返回不同结果（TOCTOU）。
 *    所以返回值里带 `lookup`（已固定的解析函数）与 `pinned`（首个地址），
 *    调用方把它塞进 `net.connect({ lookup })` / `http.request({ lookup })` 即可，
 *    与 `net-util.mjs` 的 `pinLookup` 同一思路，只是支持多地址顺序回退。
 *
 * 5. **白名单精确匹配，IP 字面量也必须写进白名单。** 如果放行「任意公网 IP」，
 *    这个代理就变成了开放正向代理（任何人借它做跳板）。允许域名 `api.example.com`
 *    不等于允许它解析出的 IP 被直接当作 host 使用 —— 那是另一条入口。
 *
 * 6. **云元数据地址即使 `allowPrivate: true` 也不放行。** 放私网是为了本地开发，
 *    而 169.254.169.254 / 100.100.100.200 / fd00:ec2::254 这类地址从不是
 *    「本地开发资源」，它们是拿实例凭据的通道。把两者捆在一个开关里，
 *    等于让「我要连本机测试服」顺手打开了凭据窃取的口子。
 *
 * 7. **解析失败也抛 `TargetDenied`。** 契约层另有 `DnsFailure`，但 B1 的对外
 *    约定是「失败一律 TargetDenied」，这样调用方只需要处理一种否决类型，
 *    不会出现「有的拒绝被 catch 了、有的漏到上层变成 500」。
 *
 * 8. **端口默认只放 80/443。** 端口是 CONNECT 唯一能看到的第二维信息，
 *    默认放开等于放弃这一维。要别的端口必须显式写进 `allowedPorts`。
 *
 * 全部函数无模块级可变状态，输入决定输出；DNS 解析通过 `options.resolve` 注入，
 * 单测里不产生真实查询。
 *
 * @module target-validator
 */

import dns from 'node:dns'
import net from 'node:net'
import { domainToASCII } from 'node:url'

import { TargetDenied } from './contract/errors.mjs'
import { ipToInt } from './net-util.mjs'

/* ============================================================
 * 类型
 * ============================================================ */

/**
 * 自定义解析函数。默认实现是 `dns.promises.lookup`，测试里注入假实现。
 *
 * 返回值允许是字符串数组，或 `{ address }` 对象数组（与 `dns.lookup(all:true)` 同形），
 * 允许同步返回或返回 Promise —— 这样测试不必包一层 async，生产实现也不受限。
 *
 * @callback ResolveFn
 * @param {string} host 已规范化的主机名（域名时才有意义）
 * @param {{ kind: 'domain'|'ipv4'|'ipv6' }} [info]
 * @returns {Promise<Array<string|{address: string}>>|Array<string|{address: string}>}
 */

/**
 * 地址分类结果。
 *
 * `ok` 表示「无需授权即可使用」；`ok:false` 但 `reason` 属于私网族时，
 * 仍可能在 `allowPrivate` 下被放行 —— 放行判定在 `isAddressPermitted()` 里做，
 * 分类本身不掺授权策略，这是为了让分类函数保持纯函数、可单独测。
 *
 * @typedef {object} AddressVerdict
 * @property {boolean} ok
 * @property {4|6|0} family
 * @property {string} address 规范化后的地址文本
 * @property {string|null} reason 拒绝原因；null 表示全球可路由
 */

/**
 * 验证选项。
 *
 * @typedef {object} ValidatorOptions
 * @property {Set<string>|string[]} [allowlist] 精确匹配的 host 集合（不含端口、不支持通配）
 * @property {boolean} [allowPrivate] 是否放行私网/回环/ULA/link-local/CGNAT（元数据地址始终拒绝）
 * @property {Set<number>|number[]} [allowedPorts] 允许的端口；缺省 `[80, 443]`
 * @property {string[]} [allowedSchemes] 允许的 scheme；缺省 `['http','https']`
 * @property {boolean} [allowCrossHostRedirect] 重定向是否允许换 host；缺省 true
 * @property {boolean} [allowSchemeDowngrade] 重定向是否允许 https→http 降级；缺省 false
 * @property {ResolveFn} [resolve] 自定义解析函数
 */

/**
 * authority 级验证结果。
 *
 * @typedef {object} ValidatedAuthority
 * @property {string} host 规范化后的 host（域名小写去尾点；IPv6 为压缩形式）
 * @property {number} port
 * @property {'domain'|'ipv4'|'ipv6'} kind
 * @property {string[]} addresses 已分类且被允许的地址，顺序与解析结果一致
 * @property {string} pinned 首个可用地址，供单地址连接使用
 * @property {Function} lookup 固定解析结果的 lookup 函数，直接传给 net/http
 */

/**
 * 完整 URL 级验证结果。
 *
 * @typedef {ValidatedAuthority & { scheme: string, path: string, query: string }} ValidatedTarget
 */

/* ============================================================
 * 常量
 * ============================================================ */

/** 域名单段允许的字符：字母数字与连字符，不能以连字符开头结尾 */
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

/** 128 位全 1，用于 IPv6 前缀掩码 */
const V6_ALL = (1n << 128n) - 1n

/**
 * 云元数据服务的 IPv4 端点。
 *
 * 这些地址**不在**「私网」语义里 —— 它们提供实例凭据/配置，
 * 一旦被代理访问就等于把凭据交给了请求方。所以单列一张表，
 * 优先级高于普通网段分类，且不受 `allowPrivate` 影响。
 */
const METADATA_V4 = new Set([
  '169.254.169.254', // AWS / GCP / Azure / OpenStack 通用元数据
  '169.254.170.2', // AWS ECS task metadata
  '169.254.169.253', // AWS VPC DNS（与元数据同段，一并拒绝）
  '100.100.100.200', // 阿里云元数据
  '168.63.129.16', // Azure WireServer / 平台虚拟 IP
  '192.0.0.192', // Oracle Cloud 元数据
])

/**
 * 云元数据服务的 IPv6 端点（压缩形式）。
 *
 * `fe80::a9fe:a9fe` 就是 169.254.169.254 的 IPv6 十六进制同址写法；
 * `fd00:ec2::254` 是 AWS 的 IPv6 元数据端点。两者都落在「私网」网段里，
 * 所以必须比网段规则先判。
 */
const METADATA_V6 = new Set([
  'fd00:ec2::254',
  'fe80::a9fe:a9fe',
])

/**
 * 不可连接的 IPv4 网段。
 *
 * 比 `ssrf-guard.mjs` 的表多了 `192.88.99.0/24`（6to4 relay anycast），
 * 并保留了文档/基准网段 —— 它们不是私网，但同样不该成为代理目标。
 */
const V4_BLOCKED = [
  ['0.0.0.0', 8, 'this_network'],
  ['10.0.0.0', 8, 'private_10'],
  ['100.64.0.0', 10, 'cgnat'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link_local'],
  ['172.16.0.0', 12, 'private_172'],
  ['192.0.0.0', 24, 'ietf_protocol'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.88.99.0', 24, 'six_to_four_relay'],
  ['192.168.0.0', 16, 'private_192'],
  ['198.18.0.0', 15, 'benchmark'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
]

/**
 * 不可连接的 IPv6 网段（不含 mapped / compatible，那两类在分类函数里特殊处理）。
 *
 * 按前缀长度降序排列：精确规则先命中，避免被大网段规则盖住。
 * `2002::/16`（6to4）与 `64:ff9b::/96`（NAT64）都是 IPv4 的封装形态，
 * 理论上可以抽出内层地址再判，但本插件只连 Cloudflare 边缘，不会用到它们，
 * 直接整段拒绝比分情况更稳（少一条「抽取写错就漏」的路径）。
 */
const V6_BLOCKED = [
  ['::', 128, 'unspecified'],
  ['::1', 128, 'loopback'],
  ['100::', 64, 'discard'],
  ['64:ff9b:1::', 48, 'nat64_local'],
  ['2001:2::', 48, 'benchmark'],
  ['64:ff9b::', 96, 'nat64'],
  ['2001::', 32, 'teredo'],
  ['2001:db8::', 32, 'documentation'],
  ['2002::', 16, 'six_to_four'],
  ['fc00::', 7, 'unique_local'],
  ['fe80::', 10, 'link_local'],
  ['fec0::', 10, 'site_local'],
  ['ff00::', 8, 'multicast'],
]

/**
 * `allowPrivate` 能放行的拒绝原因。
 *
 * 语义是「可能属于用户自己的网络」：回环、RFC1918、ULA、link-local、CGNAT、
 * 以及 `ssrf-guard.mjs` 里同样归为本地语义的 site-local。**不含** metadata、
 * documentation、benchmark、multicast 等 —— 那些从不是「我的网络」。
 */
const PRIVATE_REASONS = new Set([
  'loopback',
  'private_10',
  'private_172',
  'private_192',
  'unique_local',
  'link_local',
  'site_local',
  'cgnat',
])

/** 缺省允许端口。端口是 CONNECT 能看到的第二维信息，默认放开等于放弃这一维。 */
const DEFAULT_ALLOWED_PORTS = Object.freeze([80, 443])

/** 缺省允许 scheme。其余（file/data/javascript/ws…）一律拒绝。 */
const DEFAULT_SCHEMES = Object.freeze(['http', 'https'])

/** scheme → 缺省端口，用于 URL 未显式写端口时的补全 */
const DEFAULT_PORTS = Object.freeze({ http: 80, https: 443 })

/** 重定向降级判定用的等级。等级降低即视为 https→http 降级。 */
const SCHEME_RANK = Object.freeze({ http: 0, https: 1 })

/* ============================================================
 * IPv6 解析与格式化
 * ============================================================ */

/**
 * 把 IPv6 文本解析成 8 个 16 位分组。
 *
 * 之所以先自己解析、而不是只依赖 `net.isIPv6`：
 *   1. 分类要按前缀做位运算，需要数值形态；
 *   2. `::ffff:127.0.0.1` 这种尾部内嵌 IPv4 的写法必须能抽出来；
 *   3. 白名单比较需要统一形式（`0:0:0:0:0:0:0:1` 与 `::1` 必须视为同一主机）。
 *
 * zone id（`fe80::1%eth0`）一律返回 null —— 它表示「本机某块网卡」，
 * 在代理场景里没有任何合法用途，且会被不同平台的解析器解释成不同东西。
 *
 * @param {string} input
 * @returns {number[]|null} 8 个分组的数组；非法返回 null
 */
function parseIpv6(input) {
  let s = String(input).trim().toLowerCase()
  if (!s || s.includes('%')) return null

  // 尾部内嵌 IPv4（::ffff:127.0.0.1）先换成两组十六进制，
  // 这样后面只剩「纯十六进制分组」一种形态要处理。
  const lastColon = s.lastIndexOf(':')
  if (lastColon === -1) return null
  const maybeV4 = s.slice(lastColon + 1)
  if (maybeV4.includes('.')) {
    if (!net.isIPv4(maybeV4)) return null
    const p = maybeV4.split('.').map(Number)
    const hi = ((p[0] << 8) | p[1]) >>> 0
    const lo = ((p[2] << 8) | p[3]) >>> 0
    s = `${s.slice(0, lastColon + 1)}${hi.toString(16)}:${lo.toString(16)}`
  }

  /** @type {string[]} */
  let parts
  const dbl = s.indexOf('::')
  if (dbl === -1) {
    parts = s.split(':')
    if (parts.length !== 8) return null
  } else {
    // 只允许一个 '::'，两个以上属于畸形输入（不同实现有不同解释，不能猜）
    if (s.indexOf('::', dbl + 1) !== -1) return null
    const leftRaw = s.slice(0, dbl)
    const rightRaw = s.slice(dbl + 2)
    const left = leftRaw ? leftRaw.split(':') : []
    const right = rightRaw ? rightRaw.split(':') : []
    // '::' 至少要压缩一组，否则就等于 9 组以上，非法
    if (left.length + right.length > 7) return null
    parts = [
      ...left,
      ...new Array(8 - left.length - right.length).fill('0'),
      ...right,
    ]
  }

  const groups = []
  for (const t of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(t)) return null
    groups.push(parseInt(t, 16))
  }
  return groups.length === 8 ? groups : null
}

/**
 * 把 8 个分组格式化成 RFC 5952 的压缩形式（最长的全零段压成 `::`）。
 *
 * 规范形式是白名单精确匹配的前提：用户写 `[::1]`、`0:0:0:0:0:0:0:1`、
 * `::0.0.0.1` 时必须被认成同一个条目。
 *
 * @param {number[]} groups
 * @returns {string}
 */
function formatIpv6(groups) {
  let bestStart = -1
  let bestLen = 0
  for (let i = 0; i < 8; i += 1) {
    if (groups[i] !== 0) continue
    let j = i
    while (j < 8 && groups[j] === 0) j += 1
    const len = j - i
    if (len > bestLen) {
      bestStart = i
      bestLen = len
    }
    i = j - 1
  }
  const hex = groups.map((g) => g.toString(16))
  if (bestLen < 2) return hex.join(':')
  const left = hex.slice(0, bestStart).join(':')
  const right = hex.slice(bestStart + bestLen).join(':')
  return `${left}::${right}`
}

/**
 * 8 个分组 → 128 位整数，供前缀位运算使用。
 *
 * @param {number[]} groups
 * @returns {bigint}
 */
function v6Big(groups) {
  let n = 0n
  for (const g of groups) n = (n << 16n) | BigInt(g)
  return n
}

/**
 * 从指定下标起抽出 32 位，还原成点分 IPv4。
 * 用于 IPv4-mapped / IPv4-compatible 的「拆开再判」。
 *
 * @param {number[]} groups
 * @param {number} offset 高 16 位的下标
 * @returns {string}
 */
function v4FromGroups(groups, offset) {
  const hi = groups[offset]
  const lo = groups[offset + 1]
  return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`
}

/**
 * 前 count 组是否全为 0。
 *
 * @param {number[]} groups
 * @param {number} count
 * @returns {boolean}
 */
function leadingZero(groups, count) {
  for (let i = 0; i < count; i += 1) if (groups[i] !== 0) return false
  return true
}

/** @typedef {[string, number, string]} CidrRule */

/** IPv4 规则表（把 CIDR 预先算成 base/mask，避免每次比较都解析） */
const V4_RULES = /** @type {CidrRule[]} */ (V4_BLOCKED).map(([base, bits, reason]) => ({
  base: ipToInt(base) >>> 0,
  mask: bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0,
  reason,
}))

/**
 * IPv6 规则表（BigInt 版本）。
 *
 * 保留 `bits` 并按位长降序排序：前缀越长越精确，必须先命中。
 * 否则 `2001:db8::/32`（文档段）会被 `2001::/32` 之类更宽的规则抢先解释，
 * 拒绝原因就会指错方向，排查时非常费时。
 */
const V6_RULES = /** @type {CidrRule[]} */ (V6_BLOCKED).map(([prefix, bits, reason]) => {
  const n = v6Big(/** @type {number[]} */ (parseIpv6(prefix)))
  const mask = bits === 0 ? 0n : (((1n << BigInt(bits)) - 1n) << BigInt(128 - bits)) & V6_ALL
  return { base: n & mask, mask, bits, reason }
}).sort((a, b) => b.bits - a.bits)

/* ============================================================
 * 地址分类
 * ============================================================ */

/**
 * @param {boolean} ok
 * @param {4|6|0} family
 * @param {string} address
 * @param {string|null} reason
 * @returns {AddressVerdict}
 */
function verdict(ok, family, address, reason) {
  return { ok, family, address, reason }
}

/**
 * IPv4 分类。
 *
 * 元数据表优先于网段表：169.254.169.254 同时属于 link-local，
 * 但它的语义是「云凭据」，必须在 `allowPrivate` 下也被拒绝，
 * 所以拒绝原因要停在 `metadata` 而不是 `link_local`。
 *
 * @param {string} ip
 * @returns {AddressVerdict}
 */
function classifyIpv4(ip) {
  const n = ipToInt(ip)
  if (!Number.isFinite(n)) return verdict(false, 4, ip, 'invalid_address')
  if (METADATA_V4.has(ip)) return verdict(false, 4, ip, 'metadata')
  for (const rule of V4_RULES) {
    if (((n & rule.mask) >>> 0) === rule.base) return verdict(false, 4, ip, rule.reason)
  }
  return verdict(true, 4, ip, null)
}

/**
 * IPv6 分类。
 *
 * 判定顺序是有讲究的，不能随意调换：
 *   1. 元数据端点（fd00:ec2::254 / fe80::a9fe:a9fe）—— 它们落在 ULA 与
 *      link-local 网段里，一旦被网段规则先吃掉，`allowPrivate` 就会把它们放行；
 *   2. `::` / `::1` —— 全零与回环，语义比「前缀表」更明确；
 *   3. IPv4-mapped（`::ffff:0:0/96`）与 IPv4-compatible（`::/96`）——
 *      **抽末 32 位按 IPv4 重判**，这是本模块补上的整类绕过；
 *   4. 其余按前缀表。
 *
 * @param {number[]} groups
 * @returns {AddressVerdict}
 */
function classifyIpv6(groups) {
  const canonical = formatIpv6(groups)

  if (METADATA_V6.has(canonical)) return verdict(false, 6, canonical, 'metadata')
  if (leadingZero(groups, 8)) return verdict(false, 6, canonical, 'unspecified')
  if (groups[7] === 1 && leadingZero(groups, 7)) return verdict(false, 6, canonical, 'loopback')

  // `::ffff:a.b.c.d`：前 80 位为 0，第 6 组是 0xffff。内核连它时打的是那个 IPv4。
  if (groups[5] === 0xffff && leadingZero(groups, 5)) {
    const inner = classifyIpv4(v4FromGroups(groups, 6))
    if (inner.reason) return verdict(false, 6, canonical, `ipv4_mapped_${inner.reason}`)
    return verdict(true, 6, canonical, null)
  }

  // `::a.b.c.d`（IPv4-compatible，已废弃；某些解析器仍接受）：前 96 位为 0。
  if (leadingZero(groups, 6)) {
    const inner = classifyIpv4(v4FromGroups(groups, 6))
    if (inner.reason) return verdict(false, 6, canonical, `ipv4_compatible_${inner.reason}`)
    return verdict(true, 6, canonical, null)
  }

  const big = v6Big(groups)
  for (const rule of V6_RULES) {
    if ((big & rule.mask) === rule.base) return verdict(false, 6, canonical, rule.reason)
  }
  return verdict(true, 6, canonical, null)
}

/**
 * 统一地址分类入口：输入任意 IP 文本，输出分类结论。
 *
 * 先试 IPv4 再试 IPv6：`net.isIPv4('127.0.0.1')` 为真，
 * 而 `127.0.0.1` 不是合法 IPv6，两条路径不会互相误判。
 *
 * @param {string} raw
 * @returns {AddressVerdict}
 */
export function classifyAddress(raw) {
  const s = typeof raw === 'string' ? raw.trim() : ''
  if (!s) return verdict(false, 0, '', 'invalid_address')
  if (net.isIPv4(s)) return classifyIpv4(s)
  const groups = parseIpv6(s)
  if (!groups) return verdict(false, 0, s, 'invalid_address')
  return classifyIpv6(groups)
}

/**
 * 去掉 `ipv4_mapped_` / `ipv4_compatible_` 前缀，得到基础拒绝原因。
 *
 * 放行判定只看「基础原因」属于哪一族；前缀只影响日志可读性。
 *
 * @param {string|null} reason
 * @returns {string|null}
 */
function baseReason(reason) {
  if (!reason) return null
  for (const prefix of ['ipv4_mapped_', 'ipv4_compatible_']) {
    if (reason.startsWith(prefix)) return reason.slice(prefix.length)
  }
  return reason
}

/**
 * 一个**已分类为不可用**的地址，是否仍然被 `allowPrivate` 放行。
 *
 * 三档，顺序固定：
 *   - `metadata` 永不通过（放私网是为了连自己的开发机，不是为了连凭据服务）；
 *   - `allowPrivate` 打开时可放行私网族；
 *   - 其余一律不通过。
 *
 * @param {string|null} reason
 * @param {ValidatorOptions} opts 已归一化的选项
 * @returns {boolean}
 */
/**
 * 判断某个地址分类结果是否放行。
 *
 * 参数类型必须是 NormalizedOptions（字段必填）而不是 ValidatorOptions（全部可选）：
 * struct 类型下「可选」不能赋给「必填」，内部一律用补齐后的形态。实测 tsc 报 TS2345。
 *
 * @param {string|null} reason
 * @param {NormalizedOptions} opts
 * @returns {boolean}
 */
function isAddressPermitted(reason, opts) {
  if (!reason) return true
  const base = baseReason(reason)
  if (base === 'metadata') return false
  if (opts.allowPrivate && PRIVATE_REASONS.has(/** @type {string} */ (base))) return true
  return false
}
/* ============================================================
 * 规范化
 * ============================================================ */

/**
 * 拒绝一个目标时统一从这里造异常。
 *
 * `details` 严格只有 `{ host, reason }`：契约层要求 details 不得包含
 * Token / Cookie / 完整 URL 等敏感值，所以这里不附带原始 URL、query、
 * Header，也不带堆栈 —— 定位靠 reason 与 host 足够。
 *
 * @param {string} reason 稳定的机器可读原因
 * @param {string} [host] 已尽可能规范化的 host（用于定位）
 * @returns {TargetDenied}
 */
function denial(reason, host) {
  const h = typeof host === 'string' ? host : ''
  return new TargetDenied(`目标被拒绝：${reason}${h ? `（${h}）` : ''}`, { host: h, reason })
}

/**
 * 域名规范化。
 *
 * 三件事必须在同一步完成，否则白名单会出现「同一个域名两种写法」：
 *   1. 去掉末尾的点（`api.example.com.` 与 `api.example.com` 是同一主机）；
 *   2. 国际化域名转 punycode（`中文.example` → `xn--fiq228c.example`），
 *      否则 Unicode 形态永远匹配不到 ASCII 白名单条目；
 *   3. 小写化（DNS 大小写不敏感）。
 *
 * 另外把「看起来像 IP 的域名」提前挡掉：`2130706433`、`0x7f.0.0.1`、
 * `1.2.3` 这类写法在不同解析器里会被解释成 127.0.0.1，属于经典绕过。
 *
 * @param {string} raw
 * @returns {{ok: true, host: string, kind: 'domain'} | {ok: false, reason: string}}
 */
function normalizeDomain(raw) {
  let h = raw
  while (h.endsWith('.')) h = h.slice(0, -1)
  if (!h) return { ok: false, reason: 'empty_host' }

  if (/^\d+$/.test(h)) return { ok: false, reason: 'integer_literal' }
  if (/^0x/i.test(h) || /\.0x/i.test(h)) return { ok: false, reason: 'hex_literal' }

  const ascii = domainToASCII(h)
  if (!ascii) return { ok: false, reason: 'bad_idn' }
  const lower = ascii.toLowerCase()
  if (lower.length > 253) return { ok: false, reason: 'too_long' }

  const labels = lower.split('.')
  for (const label of labels) {
    if (!label) return { ok: false, reason: 'empty_label' }
    if (!LABEL.test(label)) return { ok: false, reason: 'bad_label' }
  }
  // 全数字标签（1.2.3 / 127.0.0.1 去掉点后的变体）在部分解析器里等价于 IP
  if (labels.every((l) => /^\d+$/.test(l) || /^0x[0-9a-f]+$/i.test(l))) {
    return { ok: false, reason: 'numeric_host' }
  }
  if (/^\d+$/.test(labels[labels.length - 1])) return { ok: false, reason: 'numeric_tld' }

  return { ok: true, host: lower, kind: 'domain' }
}

/**
 * host 规范化：域名、IPv4 字面量、IPv6 字面量（带不带方括号都认）。
 *
 * 这里**不拆端口**。端口是独立参数，原因见文件头第 1 条：按冒号切会毁掉 IPv6。
 * 若调用方误把 `host:port` 整个传进来，会得到 `host_has_port` 这个明确错误，
 * 而不是一个语焉不详的解析失败。
 *
 * @param {unknown} raw
 * @returns {{ok: true, host: string, kind: 'domain'|'ipv4'|'ipv6'} | {ok: false, reason: string}}
 */
/**
 * 域名 / IP 字面量规范化。
 *
 * `@returns` 显式联合类型，理由同 normalizePort。
 *
 * @param {unknown} raw
 * @returns {{ ok: true, host: string, kind: 'domain'|'ipv4'|'ipv6' }
 *   | { ok: false, reason: string }}
 */
function normalizeHost(raw) {
  if (typeof raw !== 'string') return { ok: false, reason: 'host_not_string' }
  // 控制字符要在 trim **之前**判：trim 会把首尾的 \n\r\t 吃掉，
  // 而这类字符是请求走私与 Header 注入的常见素材，不能被静默宽恕。
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { ok: false, reason: 'control_or_space' }
  const h = raw.trim()
  if (!h) return { ok: false, reason: 'empty_host' }
  if (/\s/.test(h)) return { ok: false, reason: 'control_or_space' }
  if (h.includes(',')) return { ok: false, reason: 'multiple_values' }
  if (h.includes('://')) return { ok: false, reason: 'has_scheme' }
  if (/[/\\?#]/.test(h)) return { ok: false, reason: 'has_path_or_query' }
  if (h.includes('@')) return { ok: false, reason: 'has_userinfo' }

  if (h.startsWith('[')) {
    if (!h.endsWith(']')) return { ok: false, reason: 'bad_ipv6_literal' }
    const inner = h.slice(1, -1)
    if (inner.includes('%')) return { ok: false, reason: 'ipv6_zone_id' }
    const groups = parseIpv6(inner)
    if (!groups) return { ok: false, reason: 'bad_ipv6_literal' }
    return { ok: true, host: formatIpv6(groups), kind: 'ipv6' }
  }
  if (net.isIPv4(h)) return { ok: true, host: h, kind: 'ipv4' }

  if (h.includes(':')) {
    const colonCount = (h.match(/:/g) ?? []).length
    if (colonCount === 1) {
      const [left, right] = h.split(':')
      if (left && /^\d{1,5}$/.test(right)) return { ok: false, reason: 'host_has_port' }
      return { ok: false, reason: 'bad_ipv6_literal' }
    }
    if (h.includes('%')) return { ok: false, reason: 'ipv6_zone_id' }
    const groups = parseIpv6(h)
    if (!groups) return { ok: false, reason: 'bad_ipv6_literal' }
    return { ok: true, host: formatIpv6(groups), kind: 'ipv6' }
  }

  return normalizeDomain(h)
}

/**
 * 端口规范化：只接受 1-65535 的十进制。
 *
 * 不接受的形态（前导 `+`、`0x`、空白、超长）全部按 `bad_port` 拒绝 ——
 * 这些正是不同 HTTP 栈之间产生「端口走私」的输入差异。
 *
 * @param {unknown} raw
 * @param {number|null} [fallback] 缺省端口
 * @returns {{ok: true, port: number} | {ok: false, reason: string}}
 */
/**
 * 端口规范化。
 *
 * `@returns` 必须显式写出联合类型：函数体里返回的是对象字面量，
 * tsc 无法从多个 return 收窄出判别式联合，调用方的 `if (!p.ok) p.reason`
 * 就会报「reason 不存在于 {ok:true}」。实测踩到。
 *
 * @param {unknown} raw
 * @param {number|null} [fallback]
 * @returns {{ ok: true, port: number } | { ok: false, reason: string }}
 */
function normalizePort(raw, fallback = null) {
  if (raw === undefined || raw === null || raw === '') {
    if (fallback == null) return { ok: false, reason: 'missing_port' }
    return { ok: true, port: fallback }
  }
  const s = typeof raw === 'number' ? String(raw) : String(raw).trim()
  if (!/^\d{1,5}$/.test(s)) return { ok: false, reason: 'bad_port' }
  const p = Number(s)
  if (!Number.isInteger(p) || p < 1 || p > 65535) return { ok: false, reason: 'bad_port' }
  return { ok: true, port: p }
}

/**
 * 解析 authority-form 的 `host:port`（CONNECT 请求行里的那一串）。
 *
 * 单独提供这个函数，是因为 CONNECT 的 target 天生是一个字符串，而调用方
 * 手写 `split(':')` 一定会毁掉 `[::1]:443`。方括号形式必须优先处理：
 * 先找到 `]`，其后才可能是端口。
 *
 * 返回结构而不是抛异常：解析失败只是「这串东西不是合法 authority」，
 * 由调用方决定回 400 还是 403；真正的安全否决（白名单/地址）在
 * `validateAuthority()` 里抛 `TargetDenied`。
 *
 * @param {unknown} raw
 * @param {number|null} [defaultPort]
 * @returns {{ok: true, host: string, port: number|null} | {ok: false, reason: string}}
 */
export function parseAuthorityTarget(raw, defaultPort = null) {
  if (typeof raw !== 'string') return { ok: false, reason: 'authority_not_string' }
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { ok: false, reason: 'control_or_space' }
  const s = raw.trim()
  if (!s) return { ok: false, reason: 'empty_authority' }
  if (/\s/.test(s)) return { ok: false, reason: 'control_or_space' }
  if (s.includes(',')) return { ok: false, reason: 'multiple_values' }
  if (s.includes('://')) return { ok: false, reason: 'has_scheme' }
  if (/[/\\?#]/.test(s)) return { ok: false, reason: 'has_path_or_query' }
  if (s.includes('@')) return { ok: false, reason: 'has_userinfo' }

  if (s.startsWith('[')) {
    const close = s.indexOf(']')
    if (close === -1) return { ok: false, reason: 'bad_ipv6_literal' }
    const host = s.slice(0, close + 1)
    const rest = s.slice(close + 1)
    if (!rest) return { ok: true, host, port: defaultPort }
    if (!rest.startsWith(':')) return { ok: false, reason: 'bad_authority' }
    const p = normalizePort(rest.slice(1), defaultPort)
    if (!p.ok) return { ok: false, reason: p.reason }
    return { ok: true, host, port: p.port }
  }

  const first = s.indexOf(':')
  const last = s.lastIndexOf(':')
  if (first !== -1 && first !== last) {
    // 多个冒号：要么是裸 IPv6（RFC 要求带方括号，但调用方可能直接给），
    // 要么是 `a:1:2` 这种畸形端口写法。能解析成 IPv6 就按「无端口」处理，
    // 否则明确报 bad_authority —— 报 multiple_colons 会误导排查方向。
    const groups = parseIpv6(s)
    if (!groups) return { ok: false, reason: 'bad_authority' }
    if (defaultPort == null) return { ok: false, reason: 'missing_port' }
    return { ok: true, host: s, port: defaultPort }
  }
  if (first === -1) {
    if (defaultPort == null) return { ok: false, reason: 'missing_port' }
    return { ok: true, host: s, port: defaultPort }
  }
  const host = s.slice(0, first)
  if (!host) return { ok: false, reason: 'empty_host' }
  const p = normalizePort(s.slice(first + 1), defaultPort)
  if (!p.ok) return { ok: false, reason: p.reason }
  return { ok: true, host, port: p.port }
}

/* ============================================================
 * 选项归一化
 * ============================================================ */

/**
 * 白名单归一化：逐条过 `normalizeHost`，非法条目丢弃并记录。
 *
 * 为什么丢弃而不是抛错：白名单来自用户配置，一条写错的条目不应该让整个
 * 代理起不来，但**必须留下痕迹**（`rejected`），否则就是静默失效 ——
 * 用户会以为「我配了却没生效」是 bug 而不是笔误。
 *
 * 空白名单意味着「什么都不允许」（fail closed），这是刻意的默认。
 *
 * @param {Set<string>|string[]|undefined} input
 * @returns {{set: Set<string>, rejected: Array<{value: string, reason: string}>}}
 */
function normalizeAllowlistEntries(input) {
  const set = new Set()
  const rejected = []
  const list = input instanceof Set ? [...input] : Array.isArray(input) ? input : []
  for (const raw of list) {
    const n = normalizeHost(raw)
    if (n.ok) set.add(n.host)
    else rejected.push({ value: String(raw), reason: n.reason })
  }
  return { set, rejected }
}

/**
 * 端口策略归一化。
 *
 * 缺省是 `[80, 443]`；显式传空数组则得到空集合，等于「一个端口都不允许」——
 * 这与缺省不同，是一个有用的「先全关再逐个开」的起点。
 *
 * @param {Set<number>|number[]|number|undefined} input
 * @returns {Set<number>}
 */
function normalizePortSet(input) {
  if (input == null) return new Set(DEFAULT_ALLOWED_PORTS)
  const list = input instanceof Set ? [...input] : Array.isArray(input) ? input : [input]
  const out = new Set()
  for (const raw of list) {
    const p = normalizePort(raw, null)
    if (p.ok) out.add(p.port)
  }
  return out
}

/**
 * 内部使用的完整选项结构（`normalizeOptions()` 的产物）。
 *
 * 与 `ValidatorOptions` 的差别：白名单与端口已从「用户写法」收敛成 Set，
 * 并附上被剔除条目的记录，便于启动时把配置笔误报到日志里。
 *
 * @typedef {object} NormalizedOptions
 * @property {Set<string>} allowlist
 * @property {Array<{value: string, reason: string}>} allowlistRejected
 * @property {boolean} allowPrivate
 * @property {Set<number>} allowedPorts
 * @property {Set<string>} allowedSchemes
 * @property {boolean} allowCrossHostRedirect
 * @property {boolean} allowSchemeDowngrade
 * @property {ResolveFn} resolve
 */

/**
 * 把调用方给的 `options` 收敛成内部使用的完整结构。
 *
 * 每次调用都重新归一化而不缓存：这个模块没有模块级状态，
 * 调用方可以在不同入口用不同策略（Forward 一套、Reverse 一套），
 * 且测试不需要清理任何全局残留。
 *
 * @param {ValidatorOptions} [options]
 * @returns {NormalizedOptions}
 */
/**
 * 把用户传入的可选参数补齐成内部完整形态。
 *
 * 调用方传 ValidatorOptions（字段全可选），内部一律用 NormalizedOptions。
 * 两者字段名相同但可选性不同，tsc 会认为不兼容 —— 这里显式标注返回类型，
 * 让下游拿到的是补齐后的形态。
 *
 * @param {ValidatorOptions} [options]
 * @returns {NormalizedOptions}
 */
function normalizeOptions(options) {
  const o = options ?? {}
  const { set: allowlist, rejected: allowlistRejected } = normalizeAllowlistEntries(o.allowlist)
  const allowedPorts = normalizePortSet(o.allowedPorts)
  const rawSchemes = Array.isArray(o.allowedSchemes) && o.allowedSchemes.length
    ? o.allowedSchemes
    : DEFAULT_SCHEMES
  const allowedSchemes = new Set(rawSchemes.map((s) => String(s).toLowerCase()))
  return {
    allowlist,
    allowlistRejected,
    allowPrivate: o.allowPrivate === true,
    allowedPorts,
    allowedSchemes,
    allowCrossHostRedirect: o.allowCrossHostRedirect !== false,
    allowSchemeDowngrade: o.allowSchemeDowngrade === true,
    resolve: typeof o.resolve === 'function' ? o.resolve : defaultResolve,
  }
}

/* ============================================================
 * 解析与 pin
 * ============================================================ */

/**
 * 默认解析：`dns.promises.lookup` 而不是 `dns.promises.resolve`。
 *
 * 差别在于 hosts 文件：lookup 会读 `/etc/hosts`（Windows 是 hosts 文件），
 * resolve 只做纯 DNS 查询。代理场景里「用户在 hosts 里指了内网域名」
 * 是常见需求，用 lookup 才符合预期；内网地址能不能真连由 `allowPrivate` 决定。
 *
 * `all: true` 保证 A 与 AAAA 都拿到 —— 只取第一条会让「混合解析」检测失效。
 *
 * @param {string} host
 * @returns {Promise<string[]>}
 */
async function defaultResolve(host) {
  // `order: 'verbatim'` 表示按解析器返回的原始顺序给结果（不重排 IPv4/IPv6）。
  // 旧版 Node 只认布尔 `verbatim`，不认识的键会被忽略，所以这里用新写法不会
  // 在旧运行时上报错，也不会改变「顺序保持解析结果」这一约定。
  const list = await dns.promises.lookup(host, { all: true, order: 'verbatim' })
  const out = []
  for (const item of list) {
    if (typeof item === 'string') out.push(item)
    else if (item && typeof item.address === 'string') out.push(item.address)
  }
  return out
}

/**
 * 调解析函数并统一出「字符串地址数组」。
 *
 * 解析失败一律转成 `TargetDenied('resolve_failed')`，理由见文件头第 7 条。
 * 注意不要把原始错误信息拼进 message：DNS 错误可能带查询名之外的内部信息，
 * 而 message 会进日志。
 *
 * @param {string} host
 * @param {{kind: 'domain'|'ipv4'|'ipv6'}} info
 * @param {ValidatorOptions} opts
 * @returns {Promise<string[]>}
 */
/**
 * 解析域名到地址列表。
 *
 * 参数类型用 NormalizedOptions（字段必填）而不是 ValidatorOptions（可选），
 * 因为这里是内部实现，调用前一定已经过 normalizeOptions 补齐。
 *
 * @param {string} host
 * @param {{ kind: 'domain'|'ipv4'|'ipv6' }} info
 * @param {NormalizedOptions} opts
 * @returns {Promise<string[]>}
 */
async function resolveAddresses(host, info, opts) {
  let raw
  try {
    raw = await /** @type {ResolveFn} */ (opts.resolve)(host, { kind: info.kind })
  } catch {
    throw denial('resolve_failed', host)
  }
  if (raw == null) throw denial('no_addresses', host)
  const list = Array.isArray(raw) ? raw : [raw]
  const out = []
  for (const item of list) {
    if (typeof item === 'string' && item.trim()) out.push(item.trim())
    else if (item && typeof item === 'object' && typeof item.address === 'string') {
      out.push(item.address.trim())
    }
  }
  if (!out.length) throw denial('no_addresses', host)
  return out
}

/**
 * 把校验过的地址钉成一个 lookup 函数。
 *
 * 这是防 DNS rebinding 的落地点：函数**忽略**传入的 hostname，永远返回
 * 校验时拿到的那批地址。因此「校验 → 连接」之间不存在第二次解析，
 * 也就不存在 TOCTOU 窗口。与 `net-util.mjs` 的 `pinLookup` 同义，
 * 区别只是支持多地址（Node 会在多个地址间顺序回退，比只钉一个更抗单点故障）。
 *
 * @param {Array<{address: string, family: 4|6}>} list 已分类且被允许的地址
 * @returns {Function} 与 `dns.lookup` 签名兼容的函数
 */
function makePinnedLookup(list) {
  const fixed = list.map((a) => ({ address: a.address, family: a.family }))
  return (_hostname, options, callback) => {
    let opts = options
    let cb = callback
    if (typeof opts === 'function') {
      cb = opts
      opts = {}
    }
    if (typeof cb !== 'function') return
    if (opts && opts.all) cb(null, fixed)
    else cb(null, fixed[0].address, fixed[0].family)
  }
}
/* ============================================================
 * 层级 1：authority 级（CONNECT）
 * ============================================================ */

/**
 * authority 级验证：只认 host + port。
 *
 * CONNECT 看不到路径，所以这里刻意**不接受 URL 字符串**。调用方若要处理
 * `host:port` 形态（CONNECT 请求行），先用 `parseAuthorityTarget()` 拆开。
 *
 * 验证顺序（先便宜后昂贵，且让错误原因指向最外层）：
 *   1. host 形态规范化 —— 语法都不对就不必查 DNS
 *   2. 端口 → 端口白名单
 *   3. host 白名单（域名与 IP 字面量一视同仁）
 *   4. 解析（IP 字面量跳过，直接进入分类）
 *   5. 地址分类 + allowPrivate 授权；**任一条不合规就整条拒绝**
 *
 * @param {string} host 域名 / IPv4 字面量 / IPv6 字面量（带或不带方括号）
 * @param {number|string|null} port
 * @param {ValidatorOptions} [options]
 * @returns {Promise<ValidatedAuthority>}
 * @throws {TargetDenied} 任何一项不通过
 */
export async function validateAuthority(host, port, options = {}) {
  const opts = normalizeOptions(options)

  const nHost = normalizeHost(host)
  if (!nHost.ok) throw denial(nHost.reason, typeof host === 'string' ? host.trim() : '')

  const nPort = normalizePort(port, null)
  if (!nPort.ok) throw denial(nPort.reason, nHost.host)

  if (!opts.allowedPorts.has(nPort.port)) throw denial('port_not_allowed', nHost.host)

  // 白名单是「入口授权」：域名写进来了才允许解析，IP 字面量写进来了才允许直连。
  // 精确匹配（Set.has），不做后缀匹配 —— 否则 `evil-example.com` 会命中
  // `example.com`，这是最容易被忽略的一类越权。
  if (!opts.allowlist.has(nHost.host)) throw denial('not_allowlisted', nHost.host)

  // IP 字面量不查 DNS：它的「解析结果」就是自己。这样既省一次往返，
  // 也避免把字面量交给可能被投毒的解析器（某些系统会把 `1.2.3.4` 交给
  // 配置的 search domain 拼成 `1.2.3.4.corp.example`）。
  const rawAddresses = nHost.kind === 'domain'
    ? await resolveAddresses(nHost.host, nHost, opts)
    : [nHost.host]

  /** @type {Array<{address: string, family: 4|6}>} */
  const allowed = []
  /** @type {AddressVerdict[]} */
  const violations = []

  for (const raw of rawAddresses) {
    const v = classifyAddress(raw)
    if (isAddressPermitted(v.reason, opts)) {
      // classifyAddress 的 family 可能是 0（无法判定），那种地址不该进 allowed。
      // 这里再收一次，既满足 4|6 的类型要求，也堵住「family 未知却放行」的缺口。
      if (v.family === 4 || v.family === 6) {
        allowed.push({ address: v.address, family: v.family })
      }
    }
    else violations.push(v)
  }

  if (violations.length) {
    // 混合结果（一部分可用、一部分不可用）单独给一个原因：它意味着解析被
    // 污染或配置异常，和「纯粹解析到私网」是两类不同的事故，排查方向不同。
    const reason = allowed.length ? 'mixed_unsafe_address' : violations[0].reason
    throw denial(/** @type {string} */ (reason), nHost.host)
  }
  if (!allowed.length) throw denial('no_addresses', nHost.host)

  return {
    host: nHost.host,
    port: nPort.port,
    kind: nHost.kind,
    addresses: allowed.map((a) => a.address),
    pinned: allowed[0].address,
    lookup: makePinnedLookup(allowed),
  }
}

/* ============================================================
 * 层级 2：完整 URL 级（Forward / Reverse）
 * ============================================================ */

/**
 * 完整 URL 级验证：scheme + authority + path + query 一起看。
 *
 * URL 的语法规范化交给 WHATWG `new URL()`：它会把国际化域名转 punycode、
 * 把百分号编码统一、把 `0x7f.0.0.1` 这类特殊 IPv4 写法还原成 `127.0.0.1`
 * （后者正好会被地址分类拦下）。自己写 URL 解析只会在这些边角上出错。
 *
 * `new URL` 解析成功的部分仍要重新走 `validateAuthority` —— 不能因为
 * 「URLParser 认为它合法」就跳过白名单与地址分类。
 *
 * @param {string} rawUrl
 * @param {ValidatorOptions} [options]
 * @returns {Promise<ValidatedTarget>}
 * @throws {TargetDenied} 任何一项不通过
 */
export async function validateTargetUrl(rawUrl, options = {}) {
  const opts = normalizeOptions(options)

  if (typeof rawUrl !== 'string') throw denial('url_not_string', '')
  // 控制字符在 trim 之前判：WHATWG 解析器会静默剥掉首尾 C0，
  // 若先 trim 再检查，`http://x/\n` 就会被当成干净输入放过去，
  // 而它在下游某个不解 strip 的实现里可能被拼成两条请求。
  if (/[\u0000-\u001f\u007f]/.test(rawUrl)) throw denial('url_has_control_chars', '')
  const trimmed = rawUrl.trim()
  if (!trimmed) throw denial('empty_url', '')
  if (/\s/.test(trimmed)) throw denial('url_has_control_chars', '')

  /** @type {URL} */
  let u
  try {
    u = new URL(trimmed)
  } catch {
    throw denial('malformed_url', '')
  }

  const scheme = u.protocol.slice(0, -1).toLowerCase()
  if (!opts.allowedSchemes.has(scheme)) throw denial('scheme_not_allowed', u.hostname)

  // userinfo 是「看起来是 A、实际连 B」的经典写法（`http://trusted.com@evil.com/`）。
  // 即便 new URL 已把 hostname 解析成 evil.com，也直接拒绝这种形态 ——
  // 合法代理请求不需要带凭据。
  if (u.username || u.password) throw denial('url_has_userinfo', u.hostname)

  const fallback = Object.prototype.hasOwnProperty.call(DEFAULT_PORTS, scheme)
    ? DEFAULT_PORTS[/** @type {'http'|'https'} */ (scheme)]
    : null
  const port = u.port === '' ? fallback : Number(u.port)
  if (port == null) throw denial('missing_port', u.hostname)

  const base = await validateAuthority(u.hostname, port, options)

  return {
    scheme,
    host: base.host,
    port: base.port,
    path: u.pathname || '/',
    query: u.search || '',
    kind: base.kind,
    addresses: base.addresses,
    pinned: base.pinned,
    lookup: base.lookup,
  }
}

/* ============================================================
 * 重定向
 * ============================================================ */

/**
 * 判断一次重定向是否允许跟随。
 *
 * 关键点是**两边都重新走完整验证**：只校验 `from` 是没用的，
 * 攻击者控制的 `Location` 才是输入。因此这个函数内部调用两次
 * `validateTargetUrl`，而不是复用 `from` 的验证结果。
 *
 * 额外两道策略闸（都可通过 options 放开）：
 *   - 降级：https → http 默认禁止（否则前面刚建立的信道保证被一行 Location 抹掉）
 *   - 跨主机：默认允许（CDN 与登录跳转都依赖它），`allowCrossHostRedirect: false`
 *     时收紧为「只能同 host 跳」
 *
 * 返回 boolean 而不抛：调用方的分支只有「跟」与「不跟」两种，
 * 把原因塞进异常会让调用点变成 try/catch 嵌套。需要原因时单独调
 * `validateTargetUrl` 即可，错误信息完全一样。
 *
 * @param {string} from 当前 URL
 * @param {string} to Location 目标 URL
 * @param {ValidatorOptions} [options]
 * @returns {Promise<boolean>}
 */
export async function isRedirectAllowed(from, to, options = {}) {
  const opts = normalizeOptions(options)
  /** @type {ValidatedTarget} */
  let a
  /** @type {ValidatedTarget} */
  let b
  try {
    a = await validateTargetUrl(from, options)
    b = await validateTargetUrl(to, options)
  } catch {
    return false
  }

  const fromRank = SCHEME_RANK[/** @type {'http'|'https'} */ (a.scheme)]
  const toRank = SCHEME_RANK[/** @type {'http'|'https'} */ (b.scheme)]
  if (typeof fromRank === 'number' && typeof toRank === 'number') {
    if (!opts.allowSchemeDowngrade && toRank < fromRank) return false
  } else if (!opts.allowSchemeDowngrade && a.scheme !== b.scheme) {
    // 未知 scheme 之间不比较等级，只要求相同 —— 放行未知组合等于给出一个
    // 谁都没审过的通道。
    return false
  }

  if (!opts.allowCrossHostRedirect && b.host !== a.host) return false

  return true
}
