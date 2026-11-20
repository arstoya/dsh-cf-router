/**
 * ensure-certificate.mjs — 按需生成测试用自签证书
 *
 * 为什么不把证书提交进仓库：公开仓库里放私钥没有任何好处，哪怕是自签的。
 * 这里在首次跑测试时用 openssl 生成到同目录（已被 .gitignore 排除）。
 *
 * 依赖 openssl：Windows 的 Git for Windows / MSYS2 自带，CI 的 ubuntu-latest 自带。
 * 找不到就抛错并说明——不要静默跳过 TLS 相关用例，那会让「测试通过」变成假象。
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const KEY = join(HERE, 'localhost.key')
const CRT = join(HERE, 'localhost.crt')
const CNF = join(HERE, 'openssl.cnf')

let cached = null

export function ensureTestCertificate() {
  if (cached) return cached
  if (existsSync(KEY) && existsSync(CRT)) {
    cached = { key: readFileSync(KEY), cert: readFileSync(CRT) }
    return cached
  }

  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', KEY, '-out', CRT,
      '-days', '3650',
      '-config', CNF, '-extensions', 'v3',
    ], { stdio: 'pipe' })
  } catch (err) {
    const msg = String(err?.stderr || err?.message || err)
    throw new Error(
      '生成测试证书失败：需要 openssl 在 PATH 里。\n' +
      `命令：openssl req -x509 ... -config ${CNF}\n` +
      `原始错误：${msg.split('\n').slice(0, 3).join(' | ')}`,
    )
  }

  cached = { key: readFileSync(KEY), cert: readFileSync(CRT) }
  return cached
}
