/**
 * state-store-v2.test.js — 状态持久化 v2 扩展（Issue #22 阶段 1）
 *
 * 覆盖三块：
 *   · v1 → v2 迁移（旧文件天然兼容）
 *   · serializeHosts：运行态 → 文件结构，只取该存的
 *   · parseHosts：文件 → 运行态，含**保守健康化**（安全关键）
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  STATE_SCHEMA_VERSION, defaultState, migrateState, buildState,
  serializeHosts, parseHosts,
} from '../../lib/state-store.mjs'

const T = 1_700_000_000_000

/* ============================================================
 * v1 → v2 迁移
 * ============================================================ */

test('v1 迁移到 v2：补空 hosts，routingMode 不变', () => {
  const r = migrateState({ version: 1, routingMode: 'direct', updatedAt: T })
  assert.equal(r.ok, true)
  assert.equal(r.fromVersion, 1)
  assert.equal(r.state.version, 2)
  assert.equal(r.state.routingMode, 'direct')
  assert.deepEqual(r.state.hosts, {}, '旧文件天然兼容，不丢数据')
})

test('v1 文件里已有的未知字段在迁移后保留', () => {
  const r = migrateState({ version: 1, routingMode: 'auto', myNote: 'keep' })
  assert.equal(r.state.myNote, 'keep')
})

test('v0 直接跨级迁到 v2', () => {
  const r = migrateState({ routingMode: 'direct', updatedAt: '2026-11-21T10:00:00.000Z' })
  assert.equal(r.fromVersion, 0)
  assert.equal(r.state.version, 2)
  assert.deepEqual(r.state.hosts, {})
})

test('buildState 默认带空 hosts', () => {
  const s = buildState({ routingMode: 'auto' }, T)
  assert.equal(s.version, STATE_SCHEMA_VERSION)
  assert.deepEqual(s.hosts, {})
})

test('buildState 传入 hosts 时原样写入', () => {
  const hosts = { h1: { candidates: {}, stats: {}, hysteresis: null } }
  const s = buildState({ routingMode: 'auto', hosts }, T)
  assert.deepEqual(s.hosts, hosts)
})

test('buildState 的 extra 不能覆盖 hosts', () => {
  const s = buildState({ routingMode: 'auto', extra: { hosts: { evil: 1 } } }, T)
  assert.deepEqual(s.hosts, {})
})

/* ============================================================
 * serializeHosts
 * ============================================================ */

function mkRuntime() {
  const candidatePools = new Map([
    ['h1', {
      candidates: new Map([
        ['1.1.1.1', {
          ip: '1.1.1.1', source: 'dns', firstSeenAt: T - 1000, lastSeenAt: T,
          lastProbeAt: T - 100, lastSuccessAt: T - 100, lastSelectedAt: T - 50,
          lastColo: 'HKG', probeCount: 42, expiresAt: T + 86_400_000,
        }],
      ]),
      lastRefreshAt: T,
    }],
  ])
  const ipStats = new Map([
    ['h1|1.1.1.1', {
      ok: 100, fail: 2, consecutiveFail: 0, failureScore: 0,
      penaltyUntil: 0, lastFailAt: 0,
      health: { state: 'healthy', halfOpenInFlight: 0, recoveryProbeSuccesses: 0,
        lastRecoveryAt: 0, metricsStale: false, enteredAt: T - 500 },
      metrics: { tcpEwmaMs: 10, tlsEwmaMs: 20, probeTtfbEwmaMs: 391,
        probeTotalEwmaMs: 420, freshTtfbEwmaMs: 380, reusedTtfbEwmaMs: 150 },
      samples: { tcp: 5, tls: 5, probeTtfb: 120, probeTotal: 120,
        freshTtfb: 80, reusedTtfb: 40, freshTtfbOverCap: 0, reusedTtfbOverCap: 0, probeTtfbOverCap: 2 },
      lastTtfbMs: 391, lastReused: true,
      recentTtfbMs: [{ ms: 391, source: 'probe' }, { ms: 402, source: 'probe' }],
    }],
  ])
  const switchState = new Map([['h1', { roundsBetter: 1, lastSwitchAt: T - 10_000 }]])
  return { candidatePools, ipStats, switchState }
}

test('序列化保留候选池生命周期字段', () => {
  const hosts = serializeHosts(mkRuntime())
  const c = hosts.h1.candidates['1.1.1.1']
  assert.equal(c.source, 'dns')
  assert.equal(c.probeCount, 42)
  assert.equal(c.firstSeenAt, T - 1000)
  assert.equal(c.lastSuccessAt, T - 100)
  assert.equal(c.lastSelectedAt, T - 50)
})

test('序列化只取探测类指标，不含真实请求指标', () => {
  const hosts = serializeHosts(mkRuntime())
  const s = hosts.h1.stats['1.1.1.1']
  assert.equal(s.metrics.probeTtfbEwmaMs, 391)
  assert.equal(s.metrics.probeTotalEwmaMs, 420)
  assert.equal('freshTtfbEwmaMs' in s.metrics, false, '真实请求指标不该持久化')
  assert.equal('reusedTtfbEwmaMs' in s.metrics, false)
  assert.equal('tcpEwmaMs' in s.metrics, false, 'tcp/tls 是每次连接重建的，不必存')
})

test('序列化不包含 recentTtfbMs 原始环（体积大头）', () => {
  const hosts = serializeHosts(mkRuntime())
  const json = JSON.stringify(hosts)
  assert.equal(json.includes('recentTtfbMs'), false)
  assert.equal(json.includes('391,"source"'), false)
})

test('序列化保留健康摘要（state / penaltyUntil / enteredAt）', () => {
  const hosts = serializeHosts(mkRuntime())
  const h = hosts.h1.stats['1.1.1.1'].health
  assert.equal(h.state, 'healthy')
  assert.equal(h.enteredAt, T - 500)
  assert.equal(h.halfOpenInFlight, undefined, '瞬态计数不存')
})

test('序列化保留切换迟滞', () => {
  const hosts = serializeHosts(mkRuntime())
  assert.deepEqual(hosts.h1.hysteresis, { roundsBetter: 1, lastSwitchAt: T - 10_000 })
})

test('完全没有价值的 ipStats 记录被跳过（省体积）', () => {
  const ipStats = new Map([
    ['h1|9.9.9.9', {
      ok: 0, fail: 0, health: { state: 'healthy', enteredAt: 0 },
      metrics: {}, samples: { probeTtfb: 0, probeTotal: 0 },
    }],
  ])
  const hosts = serializeHosts({ candidatePools: new Map(), ipStats, switchState: new Map() })
  assert.deepEqual(hosts, {}, '从没探测、也没冷却的不写')
})

test('冷却中的记录即使没有探测样本也要存', () => {
  const ipStats = new Map([
    ['h1|9.9.9.9', {
      health: { state: 'cooling', penaltyUntil: T + 60_000, enteredAt: T },
      metrics: {}, samples: { probeTtfb: 0, probeTotal: 0 },
    }],
  ])
  const hosts = serializeHosts({ candidatePools: new Map(), ipStats, switchState: new Map() })
  assert.equal(hosts.h1.stats['9.9.9.9'].health.state, 'cooling')
})

test('空输入不产生垃圾 host 条目', () => {
  const hosts = serializeHosts({
    candidatePools: new Map([['h1', { candidates: new Map() }]]),
    ipStats: new Map(),
    switchState: new Map([['h1', { roundsBetter: 0, lastSwitchAt: 0 }]]),
  })
  assert.deepEqual(hosts, {})
})

test('序列化结果可 JSON 往返', () => {
  const hosts = serializeHosts(mkRuntime())
  const back = JSON.parse(JSON.stringify(hosts))
  assert.deepEqual(back, hosts)
})

/* ============================================================
 * parseHosts：保守健康化（安全关键）
 * ============================================================ */

test('冷却已过期 → 降级为 half_open（不能直接 healthy）', () => {
  const r = parseHosts({
    h1: { stats: { '1.1.1.1': { health: { state: 'cooling', penaltyUntil: 100 } } } },
  }, 200)

  const s = r.stats.get('h1|1.1.1.1')
  assert.equal(s.health.state, 'half_open', '必须经恢复探测才能回 healthy')
  assert.equal(r.summary.demoted, 1)
})

test('冷却未过期 → 保持 cooling', () => {
  const r = parseHosts({
    h1: { stats: { '1.1.1.1': { health: { state: 'cooling', penaltyUntil: 9999 } } } },
  }, 200)
  assert.equal(r.stats.get('h1|1.1.1.1').health.state, 'cooling')
  assert.equal(r.summary.demoted, 0)
})

test('half_open 保持 half_open（不擅自升级）', () => {
  const r = parseHosts({
    h1: { stats: { '1.1.1.1': { health: { state: 'half_open', penaltyUntil: 0 } } } },
  }, 200)
  assert.equal(r.stats.get('h1|1.1.1.1').health.state, 'half_open')
})

test('恢复出来的 cooling / half_open 都标记 metricsStale', () => {
  const r = parseHosts({
    h1: { stats: {
      '1.1.1.1': { health: { state: 'cooling', penaltyUntil: 9999 } },
      '2.2.2.2': { health: { state: 'half_open' } },
      '3.3.3.3': { health: { state: 'healthy' } },
    } },
  }, 200)
  assert.equal(r.stats.get('h1|1.1.1.1').health.metricsStale, true)
  assert.equal(r.stats.get('h1|2.2.2.2').health.metricsStale, true)
  assert.equal(r.stats.get('h1|3.3.3.3').health.metricsStale, false)
})

test('瞬态计数从 0 开始（halfOpenInFlight 不恢复）', () => {
  const r = parseHosts({
    h1: { stats: { '1.1.1.1': { health: { state: 'half_open', halfOpenInFlight: 3 } } } },
  }, 200)
  const s = r.stats.get('h1|1.1.1.1')
  assert.equal(s.health.halfOpenInFlight, 0)
  assert.equal(s.health.recoveryProbeSuccesses, 0)
})

test('非法健康状态回落为 healthy', () => {
  for (const bad of ['degraded', 'dead', 42, null, undefined]) {
    const r = parseHosts({
      h1: { stats: { '1.1.1.1': { health: { state: bad } } } },
    }, 200)
    assert.equal(r.stats.get('h1|1.1.1.1').health.state, 'healthy', `${JSON.stringify(bad)}`)
  }
})

/* ============================================================
 * parseHosts：数据校验
 * ============================================================ */

test('非法条目被丢弃并计数，不抛错', () => {
  const r = parseHosts({
    h1: {
      candidates: { '1.1.1.1': 'not-an-object', '': { source: 'dns' } },
      stats: { '2.2.2.2': null },
    },
    '': {},
    bad: 'string',
  }, T)

  assert.equal(r.summary.dropped >= 2, true, `实际 dropped=${r.summary.dropped}`)
  assert.equal(r.candidates.size, 0)
})

test('非对象 hosts 返回空结构', () => {
  for (const bad of [null, undefined, 'str', 42, []]) {
    const r = parseHosts(bad, T)
    assert.equal(r.candidates.size, 0)
    assert.equal(r.stats.size, 0)
    assert.equal(r.hysteresis.size, 0)
  }
})

test('候选恢复后补齐 lastSeenAt 与 expiresAt', () => {
  const r = parseHosts({
    h1: { candidates: { '1.1.1.1': { source: 'dns', firstSeenAt: T, probeCount: 5 } } },
  }, T)
  const c = r.candidates.get('h1').get('1.1.1.1')
  assert.equal(c.probeCount, 5)
  assert.ok(Number.isFinite(c.lastSeenAt))
  assert.ok(Number.isFinite(c.expiresAt))
})

/* ============================================================
 * 端到端：serialize → JSON → parse
 * ============================================================ */

test('序列化与反序列化往返后核心字段一致', () => {
  const hosts = serializeHosts(mkRuntime())
  const json = JSON.parse(JSON.stringify(hosts))
  const r = parseHosts(json, T)

  const c = r.candidates.get('h1').get('1.1.1.1')
  assert.equal(c.source, 'dns')
  assert.equal(c.probeCount, 42)
  assert.equal(c.lastSuccessAt, T - 100)

  const s = r.stats.get('h1|1.1.1.1')
  assert.equal(s.health.state, 'healthy')
  assert.equal(s.metrics.probeTtfbEwmaMs, 391)
  assert.equal(s.samples.probeTtfb, 120)

  assert.equal(r.hysteresis.get('h1').roundsBetter, 1)
})
