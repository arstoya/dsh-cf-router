/**
 * net-util.mjs — IPv4 地址与抽样工具（Issue #14 拆分批次 1）
 *
 * 从 index.js 逐字搬出。**没有改任何逻辑**，只换了位置。
 * 这一组是纯函数：零模块级状态，输入决定输出。
 */

/**
 * 点分 IPv4 → 32 位无符号整数。
 * 任一段非法（非整数、越界、段数不对）一律返回 NaN，不做容错猜测。
 */
export function ipToInt(ip) {
  const p = String(ip).split('.').map(Number)
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return NaN
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]
}

/** 32 位整数 → 点分 IPv4 */
export function intToIp(n) {
  const v = n >>> 0
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`
}

/**
 * 在 CIDR 内均匀随机取一个地址。
 * 前缀长度限制在 /8 ~ /32，避免一次抽到超大网段。
 */
export function randInCidr(cidr) {
  const [base, bitsRaw] = String(cidr).split('/')
  const bits = Number(bitsRaw)
  if (!base || !Number.isFinite(bits) || bits < 8 || bits > 32) return null
  const start = ipToInt(base)
  if (!Number.isFinite(start)) return null
  const size = 2 ** (32 - bits)
  return intToIp(start + Math.floor(Math.random() * size))
}

/**
 * 从多个 CIDR 各抽 perRange 个地址。
 * perRange 夹在 0~10 —— 这是防呆上限，不是性能调优参数。
 */
export function sampleFromRanges(ranges, perRange) {
  const n = Math.max(0, Math.min(10, Number(perRange) || 0))
  if (!n) return []
  const out = []
  for (const r of ranges || []) {
    for (let i = 0; i < n; i += 1) {
      const ip = randInCidr(r)
      if (ip) out.push(ip)
    }
  }
  return out
}

/**
 * 把 DNS 解析钉死到指定 IP。
 *
 * 这是「验证过的解析结果就是连接时使用的地址」的实现手段（防 DNS rebinding）：
 * 校验与连接之间不再有第二次解析，也就不存在 TOCTOU 窗口。
 */
export function pinLookup(ip) {
  return (_hostname, options, cb) => {
    if (options && options.all) cb(null, [{ address: ip, family: 4 }])
    else cb(null, ip, 4)
  }
}
