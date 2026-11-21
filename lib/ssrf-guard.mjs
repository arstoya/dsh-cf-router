/**
 * ssrf-guard.mjs — 目标域名白名单与 SSRF 防护（Issue #6）
 *
 * 四层防护，任何一层不通过都拒绝：
 *   1. Authority 解析：不用 split(':')，按结构化规则解析 Host / x-cf-target
 *   2. 白名单：只允许 targets 里精确列出的域名，不做后缀匹配
 *   3. 地址分类：解析结果必须是全球可路由地址（拒绝回环/私网/链路本地/CGNAT/保留段）
 *   4. 防 rebinding：验证过的解析结果就是连接时使用的地址，不做二次无约束解析
 *
 * 为什么不能只靠「默认监听 127.0.0.1」：本机其它进程、浏览器页面（同源策略之前）
 * 都能打到这个端口。没有白名单时，任意 Host 头都会被拿去连上游。
 */

import net from 'node:net'

/** 允许的域名格式：小写字母数字与连字符，点分隔，至少两段，不允许纯数字 TLD */
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i

/**
 * 规范化一个 authority 值。
 *
 * @returns {{ok: true, host: string, port: number|null} | {ok: false, reason: string}}
 */
export function normalizeAuthority(raw, { defaultPort = null } = {}) {
  if (typeof raw !== 'string') return { ok: false, reason: 'not_a_string' }
  const trimmed = raw.trim()
  if (!trimmed) return { ok: false, reason: 'empty' }
  // 控制字符 / 空白 / 多值（逗号分隔多 Host 是经典歧义来源）
  if (/[\x00-\x20\x7f]/.test(trimmed)) return { ok: false, reason: 'control_or_space' }
  if (trimmed.includes(',')) return { ok: false, reason: 'multiple_values' }
  // 协议、路径、query、userinfo 一律拒绝
  if (trimmed.includes('://')) return { ok: false, reason: 'has_scheme' }
  if (/[\/\\?#]/.test(trimmed)) return { ok: false, reason: 'has_path_or_query' }
  if (trimmed.includes('@')) return { ok: false, reason: 'has_userinfo' }

  // IPv6 字面量一律拒绝（本插件只处理 IPv4 上游，且 [::1] 等属于危险目标）
  if (trimmed.startsWith('[')) return { ok: false, reason: 'ipv6_literal' }

  // 端口：只接受一个冒号，且端口必须是 1-65535 的十进制
  let host = trimmed
  let port = defaultPort
  const colonCount = (trimmed.match(/:/g) || []).length
  if (colonCount > 1) return { ok: false, reason: 'multiple_colons' }
  if (colonCount === 1) {
    const idx = trimmed.lastIndexOf(':')
    host = trimmed.slice(0, idx)
    const portStr = trimmed.slice(idx + 1)
    if (!/^\d{1,5}$/.test(portStr)) return { ok: false, reason: 'bad_port' }
    const p = Number(portStr)
    if (!Number.isInteger(p) || p < 1 || p > 65535) return { ok: false, reason: 'bad_port' }
    port = p
  }

  // 末尾点（FQDN 写法）去掉；统一小写
  host = host.replace(/\.+$/, '').toLowerCase()
  if (!host) return { ok: false, reason: 'empty_host' }

  // 纯 IP 字面量拒绝：IPv4 与整数形式都不允许（避免 2130706433 / 0x7f.1 之类的绕过）
  if (net.isIP(host)) return { ok: false, reason: 'ip_literal' }
  if (/^\d+$/.test(host)) return { ok: false, reason: 'integer_literal' }
  if (/^0x/i.test(host) || host.includes('0x')) return { ok: false, reason: 'hex_literal' }

  if (host.length > 253) return { ok: false, reason: 'too_long' }
  const labels = host.split('.')
  for (const l of labels) {
    if (!l) return { ok: false, reason: 'empty_label' }
    if (!LABEL.test(l)) return { ok: false, reason: 'bad_label' }
  }
  // 纯数字 TLD 是典型的十进制 IP 伪装
  if (/^\d+$/.test(labels[labels.length - 1])) return { ok: false, reason: 'numeric_tld' }

  // 单段主机名（localhost 等）在**语法上**允许，能否真正使用由白名单 + 地址分类决定。
  // 这样「显式把 localhost 写进 targets 且允许私网地址」是可用的（本地开发/测试），
  // 但任何未显式配置的单段名都会被白名单挡掉。
  return { ok: true, host, port, singleLabel: labels.length === 1 }
}

/** 把点分十进制转成 32 位无符号整数 */
function v4ToInt(ip) {
  const parts = String(ip).split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0
}

/**
 * 不该被连接的 IPv4 网段。按 RFC 分类，全部覆盖。
 * 注意：169.254.169.254 是云元数据服务，是最经典的 SSRF 目标。
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
  ['192.168.0.0', 16, 'private_192'],
  ['198.18.0.0', 15, 'benchmark'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
].map(([base, bits, reason]) => ({
  base: v4ToInt(base),
  mask: bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0,
  bits,
  reason,
}))

/**
 * 判断一个 IPv4 是否属于「不可连接」范围。
 * @returns {string|null} 命中原因，null 表示可用
 */
export function blockedIpv4(ip) {
  const n = v4ToInt(ip)
  if (n == null) return 'invalid_ip'
  for (const blk of V4_BLOCKED) {
    if (((n & blk.mask) >>> 0) === blk.base) return blk.reason
  }
  return null
}

/**
 * 从 DNS 结果里筛出可用地址。
 * 任何一条命中黑名单就整体拒绝 —— 不做「挑一个安全的用」，
 * 因为混合结果本身说明解析被污染了。
 *
 * @returns {{ok: boolean, ips: string[], reason?: string, hit?: string}}
 */
export function filterResolvedIps(ips) {
  const list = (Array.isArray(ips) ? ips : []).filter((x) => typeof x === 'string')
  if (!list.length) return { ok: false, ips: [], reason: 'no_addresses' }
  const blocked = []
  for (const ip of list) {
    const why = blockedIpv4(ip)
    if (why) blocked.push(`${ip}(${why})`)
  }
  if (blocked.length) {
    return { ok: false, ips: list, reason: 'blocked_address', hit: blocked.join(',') }
  }
  return { ok: true, ips: list }
}

/**
 * 规范化白名单：把配置里的 targets 全部校验一遍并去重。
 * 非法条目直接丢弃并记录，而不是让它们留在白名单里。
 */
export function normalizeAllowlist(targets) {
  const allowed = new Set()
  const rejected = []
  for (const raw of Array.isArray(targets) ? targets : []) {
    const n = normalizeAuthority(raw)
    if (n.ok) allowed.add(n.host)
    else rejected.push({ value: String(raw), reason: n.reason })
  }
  return { allowed, rejected }
}

/**
 * 判断一个已规范化的 Host 是否在白名单内。
 * **精确匹配**，不做后缀匹配 —— 否则 `evil-example.com` 能命中 `example.com` 的后缀。
 */
export function isAllowedHost(host, allowedSet) {
  if (typeof host !== 'string' || !host) return false
  return allowedSet.has(host)
}

/**
 * 判断白名单里是否存在本机/私网目标。
 * 用于启动时提示：配置了私网目标意味着地址层的 SSRF 防护被有意放开。
 */
export function hasLocalTargets(allowedSet) {
  for (const h of allowedSet) {
    if (h === 'localhost' || !h.includes('.')) return true
  }
  return false
}
