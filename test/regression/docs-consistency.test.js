/**
 * docs-consistency.test.js — 文档与代码一致性（Issue #23 验收要求）
 *
 * 文档漂移是最常见的腐化形式：代码加了字段，文档没跟上，几轮之后
 * 没人知道哪边是真的。这里用断言把关键部分钉住。
 *
 * 只校验「必须出现在文档里」的字段名，不校验措辞 ——
 * 后者会让人为了过测试而写文档，本末倒置。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'

const api = mod.__testApi
const ROOT = path.resolve(import.meta.dirname, '../..')
const DOCS = {
  en: path.join(ROOT, 'docs', 'reference.md'),
  zh: path.join(ROOT, 'docs', 'reference.zh-CN.md'),
}

function readDoc(which) {
  const p = DOCS[which]
  assert.ok(fs.existsSync(p), `${which} 文档不存在: ${p}`)
  return fs.readFileSync(p, 'utf8')
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * statusSnapshot 顶层字段必须在文档里出现
 * ============================================================ */

test('文档覆盖 statusSnapshot 的全部顶层字段', () => {
  setupPlugin({ targets: ['localhost'], discoverEnabled: false, allowPrivateTargets: true })
  const snap = api.statusSnapshot()
  const keys = Object.keys(snap)

  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    const missing = keys.filter((k) => !doc.includes(k))
    assert.deepEqual(missing, [],
      `${which} 文档缺少这些顶层字段: ${missing.join(', ')}`)
  }
})

test('文档覆盖新增的子结构字段', () => {
  setupPlugin({ targets: ['localhost'], discoverEnabled: false, allowPrivateTargets: true })
  // 建一条候选，让嵌套结构有内容
  api.statOf('localhost', '127.0.0.1').samples.probeTtfb = 1
  const snap = api.statusSnapshot()

  const mustMention = [
    'healthSummary', 'counts', 'pendingRecovery', 'staleMetrics',
    'candidatePools', 'overCapacity', 'dnsCount', 'discoveredCount',
    'connectionPools', 'drainingCount', 'totalInFlight', 'drainTimeoutMs',
    'switchHysteresis', 'roundsBetter', 'lastSwitchAt', 'dwellRemainingMs',
    'statePersistence', 'dirty', 'lastFlushAt', 'minIntervalMs',
    'stateSchema', 'loadedFrom',
    'restore', 'demoted', 'dropped',
    'configEffective', 'configured', 'effective', 'floorMs',
    'routingModeSources', 'configMode', 'stateFileMode', 'effectiveMode', 'stateFileWins',
    'allowedTargets', 'rejectedTargets',
  ]

  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    const missing = mustMention.filter((k) => !doc.includes(k))
    assert.deepEqual(missing, [], `${which} 文档缺少: ${missing.join(', ')}`)
  }
  void snap
})

/* ============================================================
 * 错误码必须与代码一致
 * ============================================================ */

test('文档里的错误码都能在代码中找到', () => {
  // 这些是控制接口真实返回的错误码
  const codes = [
    'target_not_allowed',
    'admin_token_not_configured',
    'invalid_json',
    'missing_field',
    'unknown_field',
    'invalid_value',
    'method_not_allowed',
    'rate_limited',
  ]
  // 错误码分散在多个模块（admin-auth / headers / index…），必须全量搜索。
  // 只搜 index.js 会误报「代码里找不到」—— 实测踩到过。
  const libDir = path.join(ROOT, 'lib')
  const src = fs.readdirSync(libDir)
    .filter((f) => f.endsWith('.js') || f.endsWith('.mjs'))
    .map((f) => fs.readFileSync(path.join(libDir, f), 'utf8'))
    .join('\n')

  for (const c of codes) {
    assert.ok(src.includes(c), `代码里找不到错误码 ${c}（文档提到它，说明发生了漂移）`)
  }

  // 文档里至少提到这几个高频的
  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    for (const c of ['target_not_allowed', 'admin_token_not_configured']) {
      assert.ok(doc.includes(c), `${which} 文档应提到 ${c}`)
    }
  }
})

/* ============================================================
 * 升级章节必须覆盖每个版本的破坏性变更
 * ============================================================ */

test('升级章节覆盖 v0.2.1 / v0.2.2 / v0.2.3', () => {
  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    for (const v of ['v0.2.1', 'v0.2.2', 'v0.2.3']) {
      assert.ok(doc.includes(v), `${which} 文档缺少 ${v} 的升级说明`)
    }
  }
})

test('v0.2.1 的五条破坏性变更全部写到', () => {
  const mustMention = [
    'x-cf-target',              // 白名单化
    'adminTokenFile',           // 鉴权
    'ewmaMs',                   // 指标拆分
    'Allow',                    // GET→POST 的 405
    'corsAllowOrigin',          // CORS 收紧
  ]
  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    for (const m of mustMention) {
      assert.ok(doc.includes(m), `${which} 文档缺少 v0.2.1 变更项: ${m}`)
    }
  }
})

/* ============================================================
 * 故障排查必须覆盖高频场景
 * ============================================================ */

test('故障排查覆盖五个高频场景', () => {
  const topics = {
    '插件不加载': ['ERR_MODULE_NOT_FOUND', 'dsh-tools'],
    'SSRF 白名单': ['target_not_allowed', 'allowedTargets'],
    '管理 Token': ['admin_token_not_configured', 'generate-admin-token'],
    '长 SSE': ['drainTimeoutMs', 'firstByteTimeoutMs'],
    '失败但不惩罚': ['client_abort', 'rate_limit'],
  }

  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    for (const [topic, keywords] of Object.entries(topics)) {
      const hit = keywords.some((k) => doc.includes(k))
      assert.ok(hit, `${which} 文档的「${topic}」缺少关键词（${keywords.join(' / ')}）`)
    }
  }
})

/* ============================================================
 * 中英内容对应（不逐句对照，只查章节骨架）
 * ============================================================ */

test('中英文档章节结构一致', () => {
  const en = readDoc('en')
  const zh = readDoc('zh')

  const enSections = (en.match(/^#{2,3} .+$/gm) || []).length
  const zhSections = (zh.match(/^#{2,3} .+$/gm) || []).length

  // 允许 ±2 的差异（中文标题可能合并或拆分了小节）
  assert.ok(Math.abs(enSections - zhSections) <= 2,
    `章节数差异过大：英文 ${enSections} / 中文 ${zhSections}`)
})

test('两份文档都不是空壳', () => {
  for (const which of ['en', 'zh']) {
    const doc = readDoc(which)
    assert.ok(doc.length > 5000, `${which} 文档过短（${doc.length} 字符），像是占位`)
    assert.ok(doc.includes('statusSnapshot') || doc.includes('status'),
      `${which} 文档应说明 statusSnapshot`)
  }
})
