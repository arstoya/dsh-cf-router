/**
 * admin-auth.mjs — 管理接口身份验证与访问保护（Issue #8）
 *
 * 三层，缺一不可：
 *   1. 来源层：Host 校验（防 DNS rebinding）+ Origin 校验（防浏览器跨站）
 *   2. 凭据层：Bearer Token，时序安全比较
 *   3. 频率层：按来源 + 接口分类限流，避免管理操作被误锁
 *
 * 设计约束（评审确认）：
 *   · Token 不得写入日志、错误信息或状态快照
 *   · 不把长期密钥放进可提交的 cordis.patch.yml —— 优先从文件读
 *   · Origin 缺失的非浏览器客户端（curl / DSH）不受 Origin 检查影响，
 *     身份凭据是 Token，Origin 只是浏览器来源的一道附加防护
 *   · 进程内 DSH 工具调用不经过 HTTP，不该被迫重新认证
 *   · 未配置 Token 时不得静默开放
 */

import fs from 'node:fs'
import crypto from 'node:crypto'

/* ---------- Token 读取 ---------- */

/**
 * 从配置文件读取 Token。文件缺失或为空返回空串。
 * **不缓存到日志，也不出现在任何返回值里之外的地方。**
 */
export function readTokenFile(filePath) {
  if (!filePath) return ''
  try {
    const raw = fs.readFileSync(filePath, 'utf8').trim()
    // 允许带注释行，只取第一个非注释非空行
    for (const line of raw.split('\n')) {
      const t = line.trim()
      if (!t || t.startsWith('#')) continue
      return t
    }
    return ''
  } catch {
    return ''
  }
}

/** 当前生效的管理 Token（配置直填优先，其次文件） */
export function resolveAdminToken(cfg) {
  const direct = String((cfg && cfg.adminToken) || '').trim()
  if (direct) return direct
  return readTokenFile(String((cfg && cfg.adminTokenFile) || '').trim())
}

/** 生成一个密码学安全的 Token（供脚本/工具使用） */
export function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url')
}

/**
 * 时序安全的 Token 比较。
 *
 * 用 `crypto.timingSafeEqual` 而不是 `===`：后者在首个不同字节就返回，
 * 攻击者可以通过响应时间逐字节猜出 Token。长度不同直接返回 false
 * （长度本身不敏感，可以先比）。
 */
export function safeTokenEqual(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false
  if (!provided || !expected) return false
  const a = Buffer.from(provided, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  if (a.length !== b.length) return false
  try {
    return crypto.timingSafeEqual(a, b)
  } catch {
    return false
  }
}

/** 从 Authorization 头提取 Bearer Token（大小写不敏感） */
export function extractBearer(headers) {
  const raw = headers && (headers.authorization || headers.Authorization)
  if (typeof raw !== 'string') return ''
  const m = /^\s*bearer\s+(\S+)\s*$/i.exec(raw)
  return m ? m[1] : ''
}

/* ---------- 来源层 ---------- */

/**
 * 回环/本机的**可达名**。刻意不含 `0.0.0.0`：
 * 它是「监听所有接口」的配置值，不是客户端能访问的名字。
 */
const LOOPBACK_NAMES = new Set(['127.0.0.1', 'localhost', '::1'])

/**
 * 「监听地址是否是回环」的判断。
 * `0.0.0.0` / 空值表示监听所有接口 —— 此时部署者已显式放开网络可达性，
 * Host 校验不该再假装是回环部署。
 */
export function listensOnLoopback(listenHost) {
  const h = String(listenHost || '').trim().toLowerCase()
  if (!h || h === '0.0.0.0' || h === '::') return false
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h.startsWith('127.')
}

/** 提取 Host 头里的主机名（宽松：去端口、去方括号、小写、去末尾点） */
export function hostnameOf(hostHeader) {
  let h = String(hostHeader || '').trim().toLowerCase()
  if (!h) return ''
  if (h.startsWith('[')) {
    const end = h.indexOf(']')
    if (end > 0) h = h.slice(1, end)
  } else {
    const i = h.lastIndexOf(':')
    if (i >= 0) h = h.slice(0, i)
  }
  return h.replace(/\.+$/, '')
}

/** 判断主机名是否属于回环/本机 */
export function isLoopbackHost(hostname) {
  return LOOPBACK_NAMES.has(String(hostname || '').toLowerCase())
}

/**
 * Host 校验：防 DNS rebinding。
 *
 * 场景：攻击者把自己的域名解析到 127.0.0.1，诱导受害者浏览该页面，
 * 页面 JS 请求 `http://evil.example:8787/__router/reset`。
 * 此时 Host 是 `evil.example`，而不是 `127.0.0.1` —— 必须拒绝。
 *
 * 只在监听地址是回环时生效：监听在回环上，任何非回环 Host 都不该到达。
 *
 * @returns {string|null} 拒绝原因，null 表示通过
 */
export function checkHost(hostHeader, listenHost) {
  const hostname = hostnameOf(hostHeader)
  if (!hostname) return 'missing_host'
  if (!listensOnLoopback(listenHost)) return null
  if (isLoopbackHost(hostname)) return null
  return 'host_not_loopback'
}

/**
 * Origin 校验：防浏览器跨站调用管理接口。
 *
 * **只在请求带 Origin 头时才检查** —— curl / DSH / 服务端脚本不发 Origin，
 * 它们的身份凭据是 Token。误伤非浏览器客户端是最容易犯的错。
 *
 * @returns {string|null}
 */
export function checkOrigin(originHeader, allowedOrigins) {
  const origin = String(originHeader || '').trim()
  if (!origin) return null                    // 非浏览器请求，交给 Token
  const list = Array.isArray(allowedOrigins) ? allowedOrigins.map((o) => String(o).trim()).filter(Boolean) : []
  if (!list.length) return 'origin_not_allowed'   // 没配白名单 = 不接受任何跨源
  if (list.includes(origin)) return null
  return 'origin_not_allowed'
}

/* ---------- 频率层 ---------- */

/**
 * 固定窗口限流。
 *
 * 按 `key` 分桶（来源 + 接口分类）。刻意用固定窗口而不是滑动窗口：
 * 管理操作是低频人工操作，窗口边界处多放行几次无所谓，
 * 而实现越简单越不容易把正常操作误锁。
 */
export function createRateLimiter({ limit, windowMs, now = () => Date.now() }) {
  const buckets = new Map()

  return {
    /** @returns {{ok: boolean, remaining: number, retryAfterMs: number}} */
    hit(key) {
      const t = now()
      let b = buckets.get(key)
      if (!b || t - b.start >= windowMs) {
        b = { start: t, count: 0 }
        buckets.set(key, b)
      }
      b.count += 1
      const remaining = Math.max(0, limit - b.count)
      return {
        ok: b.count <= limit,
        remaining,
        retryAfterMs: b.count <= limit ? 0 : Math.max(0, windowMs - (t - b.start)),
      }
    },
    reset() { buckets.clear() },
    /** 仅供测试观察 */
    size() { return buckets.size },
  }
}

/* ---------- 组合判定 ---------- */

/**
 * 判定一次管理请求是否放行。
 *
 * @param {object} input
 * @param {object} input.headers 请求头
 * @param {string} input.remoteAddr
 * @param {string} input.listenHost
 * @param {string} input.route
 * @param {object} input.cfg
 * @param {object} input.rl 限流器
 * @param {boolean} input.mutating 是否修改型接口
 * @param {() => string} input.getToken 取当前 Token（延迟解析，避免每请求读盘）
 * @returns {{ok: true} | {ok: false, status: number, error: string, message: string, extra?: object}}
 */
export function authorize(input) {
  const { headers = {}, remoteAddr = '', listenHost = '', route = '', cfg = {}, rl, mutating, getToken } = input

  // ---- 1. Host（防 rebinding，任何请求都要过） ----
  const hostVerdict = checkHost(headers.host, listenHost)
  if (hostVerdict) {
    return {
      ok: false,
      status: 403,
      error: 'forbidden_host',
      message: `Host 校验失败（${hostVerdict}）：监听回环时只接受回环/本机 Host，防止 DNS rebinding`,
    }
  }

  // ---- 2. Origin（只对浏览器生效） ----
  const originVerdict = checkOrigin(headers.origin, cfg.adminAllowedOrigins)
  if (originVerdict) {
    return {
      ok: false,
      status: 403,
      error: 'forbidden_origin',
      message: '该来源未被 adminAllowedOrigins 允许',
      extra: { origin: String(headers.origin).slice(0, 120) },
    }
  }

  // ---- 3. 频率 ----
  if (rl) {
    const bucketKey = `${remoteAddr}|${mutating ? 'write' : 'read'}`
    const r = rl.hit(bucketKey)
    if (!r.ok) {
      return {
        ok: false,
        status: 429,
        error: 'rate_limited',
        message: '触发了管理接口频率限制，稍后重试',
        extra: { retryAfterMs: r.retryAfterMs },
      }
    }
  }

  // ---- 4. 凭据 ----
  const token = String(getToken() || '')
  const protectThis = mutating || Boolean(cfg.adminProtectStatus)

  if (!protectThis) return { ok: true }   // 只读且未要求保护

  if (token) {
    const provided = extractBearer(headers)
    if (!provided) {
      return {
        ok: false,
        status: 401,
        error: 'unauthorized',
        message: '需要 Authorization: Bearer <adminToken>',
        extra: { authRequired: true },
      }
    }
    if (!safeTokenEqual(provided, token)) {
      // 注意：不把 Token 写进日志或响应
      return { ok: false, status: 401, error: 'unauthorized', message: 'Token 不匹配' }
    }
    return { ok: true }
  }

  // 未配置 Token：只有显式开启逃生舱、且请求来自回环时才放行
  if (cfg.allowUnauthenticatedLocalAdmin) {
    if (isLoopbackHost(hostnameOf(remoteAddr)) || remoteAddr === '127.0.0.1' || remoteAddr === '::1') {
      return { ok: true }
    }
    return {
      ok: false,
      status: 403,
      error: 'forbidden',
      message: '未配置 adminToken，且来源不是回环地址',
    }
  }

  return {
    ok: false,
    status: 403,
    error: 'admin_token_not_configured',
    message: '管理接口未配置 adminToken，修改型操作已禁用。请配置 adminToken 或 adminTokenFile（可用 scripts/generate-admin-token.mjs 生成）',
    extra: { authRequired: true, tokenConfigured: false },
  }
}
