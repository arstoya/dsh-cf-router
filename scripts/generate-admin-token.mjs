#!/usr/bin/env node
/**
 * generate-admin-token.mjs — 生成管理接口 Token
 *
 * 用法：
 *   node scripts/generate-admin-token.mjs                 # 打印到 stdout
 *   node scripts/generate-admin-token.mjs --write <path>  # 写入文件（权限 0600）
 *   node scripts/generate-admin-token.mjs --check <path>  # 用现有 Token 做一次自检
 *
 * 为什么要有这个脚本：
 *   Issue #8 要求 Token 用密码学安全随机源生成，且**不要把长期密钥提交进
 *   cordis.patch.yml**。所以推荐流程是：
 *     1. 本脚本 --write 到工作区外的文件
 *     2. 在 patch 里配 adminTokenFile 指向它
 *   这样 Token 既不可猜测、也不会进版本库。
 */
import fs from 'node:fs'
import path from 'node:path'
import { generateToken, readTokenFile } from '../lib/admin-auth.mjs'

const argv = process.argv.slice(2)
const opt = (n) => {
  const i = argv.indexOf(n)
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null
}

const writeTo = opt('--write')
const checkPath = opt('--check')

if (checkPath) {
  const t = readTokenFile(checkPath)
  if (!t) {
    console.error(`✗ ${checkPath} 不存在或没有有效 Token`)
    process.exit(1)
  }
  console.log(`✓ ${checkPath} 可读，Token 长度 ${t.length}（不回显内容）`)
  console.log(`  片段：${t.slice(0, 3)}…${t.slice(-2)}（仅用于人工比对）`)
  process.exit(0)
}

const token = generateToken(32)

if (writeTo) {
  const abs = path.resolve(writeTo)
  fs.mkdirSync(path.dirname(abs), { recursive: true })
  // 已存在则不覆盖，避免把正在用的 Token 冲掉
  if (fs.existsSync(abs)) {
    const existing = readTokenFile(abs)
    if (existing) {
      console.error(`✗ ${abs} 已存在且有内容，未覆盖。要重新生成请先自行删除。`)
      process.exit(1)
    }
  }
  fs.writeFileSync(abs, `# dsh-cf-router 管理 Token（勿提交进版本库）\n${token}\n`, { encoding: 'utf8', mode: 0o600 })
  console.log(`✓ 已写入 ${abs}（权限 0600）`)
  console.log(`  在插件配置里设置：adminTokenFile: "${abs}"`)
  console.log('  并确认该路径已在 .gitignore 中。')
} else {
  // 输出到 stdout 供管道使用；不写任何文件
  console.log(token)
}
