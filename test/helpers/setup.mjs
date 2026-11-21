/**
 * setup.mjs — 测试统一装配
 *
 * 存在的理由：插件的 statePath 在 cfg.stateFile 为空时会落到
 * `$DSH_HOME/cf-router-state.json` —— 那是**正在运行的插件的真实状态文件**。
 * 测试一旦调 setRoutingMode 就会把它改掉（实测踩过：把真实文件写成了 direct）。
 *
 * 所以测试一律通过这里装配配置，强制注入进程级临时 stateFile，
 * 并在收尾时删除。任何测试文件都不该自己拼 cfg。
 */
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'

import * as mod from '../../lib/index.js'

const api = mod.__testApi

let counter = 0
const created = new Set()

/** 一个本次进程独有的临时状态文件路径（不会与其它测试进程撞） */
export function tempStateFile(tag = 'state') {
  counter += 1
  const p = path.join(os.tmpdir(), `cfr-test-${process.pid}-${counter}-${tag}.json`)
  created.add(p)
  try { fs.unlinkSync(p) } catch { /* 不存在更好 */ }
  return p
}

/** 删除本进程创建过的所有临时状态文件 */
export function cleanupTempFiles() {
  for (const p of created) {
    try { fs.unlinkSync(p) } catch { /* ignore */ }
    created.delete(p)
  }
}

/**
 * 装配插件：清状态 → 注入依赖 → 装配置（强制临时 stateFile）。
 * @param {object} [overrides] 覆盖默认测试配置
 * @param {object} [opts]
 * @param {Function} [opts.now] 假时钟的取时函数
 */
export function setupPlugin(overrides = {}, opts = {}) {
  api.reset()

  if (opts.now) api.deps.now = opts.now

  const config = {
    targets: ['localhost'],
    discoverEnabled: false,
    stateFile: tempStateFile(),
    // 测试一律打本机 https fixture（127.0.0.1），需要显式放开地址分类层。
    // 第一层格式校验与第二层白名单仍然生效 —— 这恰好验证了「放开地址层
    // 不等于放开授权」。
    allowPrivateTargets: true,
    ...overrides,
  }
  // 若调用方显式给了 stateFile（比如测试持久化本身），尊重它
  api.configure(config)
  return { api, config }
}

/** 收尾：关代理 + 清状态 + 删临时文件 */
export function teardownPlugin() {
  try { api.closeProxy() } catch { /* ignore */ }
  try { mod.__resetForTest() } catch { /* ignore */ }
  cleanupTempFiles()
}

export { api, mod }
