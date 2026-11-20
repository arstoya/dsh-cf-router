/**
 * router-race.test.js — 路由并发状态竞争回归（Issue #2）
 *
 * 缺陷背景（改造前）：
 *   noteSuccess() 里有一句 `if (currentIp.get(host) !== ip) currentIp.set(host, ip)`，
 *   于是「旧请求迟到的成功回调」能把已经切走的线路改回来。
 *
 *   时序：A 故障 → 切到 B → A 的旧请求姗姗来迟返回成功 → 线路又变回 A。
 *   后果是线路反复横跳，甚至重新启用已判定故障的节点。
 *
 * 本文件锁定修复后的契约：
 *   1. 成功回调只更新该 IP 的统计，**永远不改路由**
 *   2. 路由只由 switchRoute() 改，且每次真切换递增 generation
 *   3. 旧失败不能把非当前线路重新设为当前
 *   4. 旧探测晚于新探测完成时，不能覆盖新结果
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'localhost'

/** 装配：假时钟 + 两/三个候选 + 100ms 冷却 */
function setup(overrides = {}) {
  const clock = createClock()
  const ctx = setupPlugin(
    {
      failThreshold: 2,
      cooldownMs: 60_000,
      ewmaAlpha: 0.5,
      ewmaMaxMs: 3000,
      ...overrides,
    },
    { now: clock.now },
  )
  return { clock, api: ctx.api }
}

function seed(entries) {
  api.state().hosts.set(HOST, {
    ips: entries.map((e) => e.ip),
    results: entries.map((e) => ({
      ip: e.ip,
      okCount: e.okCount ?? 3,
      samples: 3,
      ttfbMedian: e.median,
      ttfbBest: e.median,
      totalMedian: (e.median ?? 0) + 20,
      tcpMedian: 10,
      tlsMedian: 20,
      median: e.median,
      best: e.median,
      colo: 'HKG',
      excluded: null,
    })),
    lastProbeAt: api.deps.now(),
    error: null,
  })
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 场景 A：旧请求迟到成功
 * ============================================================ */

test('场景 A：旧请求迟到成功不会把路由改回旧 IP', () => {
  const { clock } = setup()
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 300 },
  ])

  // 初始路由 A，generation=1
  api.switchRoute(HOST, '203.0.113.1', 'initial')
  const genAtRequest = api.getRouteGeneration(HOST)
  assert.equal(api.state().currentIp.get(HOST), '203.0.113.1')

  // A 连续失败两次 → 判死并切到 B，generation=2
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'boom', kind: 'error' }, genAtRequest)
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'boom', kind: 'error' }, genAtRequest)
  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', '应已切到 B')
  const genNow = api.getRouteGeneration(HOST)
  assert.equal(genNow, genAtRequest + 1, '每次真切换递增一次')

  const okBefore = api.statOf(HOST, '203.0.113.1').ok

  // A 的旧请求迟到成功（携带旧 generation）
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 120, reused: false }, genAtRequest)

  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', '路由必须仍是 B')
  assert.equal(api.getRouteGeneration(HOST), genNow, 'generation 不该因成功回调变化')
  assert.equal(api.statOf(HOST, '203.0.113.1').ok, okBefore + 1, '旧 IP 的统计仍要更新')
})

/* ============================================================
 * 场景 B：旧请求迟到失败
 * ============================================================ */

test('场景 B：旧请求迟到失败不会把非当前线路重新设为当前', () => {
  const { clock } = setup()
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 300 },
  ])

  api.switchRoute(HOST, '203.0.113.1', 'initial')
  const genA = api.getRouteGeneration(HOST)

  // 主动切到 B（模拟探测发现更快）
  api.switchRoute(HOST, '203.0.113.2', 'probe:better')
  const genB = api.getRouteGeneration(HOST)
  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2')

  const failBefore = api.statOf(HOST, '203.0.113.1').fail

  // A 的旧请求迟到失败两次（足以判死）
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'late', kind: 'error' }, genA)
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'late', kind: 'error' }, genA)

  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', 'B 不能被覆盖')
  assert.equal(api.getRouteGeneration(HOST), genB, 'generation 不该变')
  assert.equal(api.statOf(HOST, '203.0.113.1').fail, failBefore + 2, '失败统计仍要记')
  assert.ok(api.statOf(HOST, '203.0.113.1').penaltyUntil > clock.now(), 'A 仍应被判死冷却')
})

test('场景 B2：A→B→A 之后，带过期 generation 的失败不能驱动切换', () => {
  // 这条是 generation 作为「第二道保护」的用武之地：
  // 光看「该 IP 是否仍是当前线路」判断不出来 —— A 走了又回来，IP 比对会认为「还是当前」。
  // 但那个请求代表的是更早一轮的观测，不该用来否决之后的新决策。
  const { clock } = setup({ failThreshold: 2 })
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 300 },
  ])

  api.switchRoute(HOST, '203.0.113.1', 'initial')      // gen 1
  const genOld = api.getRouteGeneration(HOST)

  api.switchRoute(HOST, '203.0.113.2', 'probe:better')  // gen 2
  api.switchRoute(HOST, '203.0.113.1', 'probe:back')    // gen 3，回到 A

  assert.equal(api.state().currentIp.get(HOST), '203.0.113.1', '路由已回到 A')
  const genNow = api.getRouteGeneration(HOST)
  const failBefore = api.statOf(HOST, '203.0.113.1').fail
  const switchesBefore = api.state().switches.length

  // 带 gen=1 的旧失败，即使「IP 是当前线路」也必须只记统计、不切换
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'stale', kind: 'error' }, genOld)
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'stale', kind: 'error' }, genOld)

  assert.equal(api.getRouteGeneration(HOST), genNow, '路由不该被旧请求驱动')
  assert.equal(api.state().switches.length, switchesBefore, '不该产生新的切换记录')
  assert.equal(api.state().currentIp.get(HOST), '203.0.113.1', '路由仍是 A')
  assert.equal(api.statOf(HOST, '203.0.113.1').fail, failBefore + 2, '失败统计仍要记')
  assert.ok(api.statOf(HOST, '203.0.113.1').penaltyUntil > clock.now(), 'A 仍应被判死冷却')
})

test('场景 B3：当前 generation 的失败可以正常驱动切换', () => {
  setup({ failThreshold: 2 })
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 300 },
  ])
  api.switchRoute(HOST, '203.0.113.1', 'initial')
  const gen = api.getRouteGeneration(HOST)

  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'real', kind: 'error' }, gen)
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'real', kind: 'error' }, gen)

  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', '当前版本的失败应能触发切换')
})

test('结构性优先：即使 generation 匹配，成功回调依然不能改路由', () => {
  // 第一道保护（回调无权写 currentIp）与第二道（版本）是两件事。
  // 这条用例证明：把 generation 给成「完全正确」的值，成功回调照样改不了路由。
  setup()
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 200 },
  ])
  api.switchRoute(HOST, '203.0.113.2', 'initial')

  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 30, reused: false }, api.getRouteGeneration(HOST))

  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', '成功回调无论如何都不改路由')
})

/* ============================================================
 * 场景 C：旧探测任务迟到
 * ============================================================ */

test('场景 C：旧探测晚于新探测完成时不能覆盖新结果', async () => {
  setup()

  // 先登记一个「新探测」的结果
  seed([{ ip: '203.0.113.9', median: 42 }])
  const genAfterNew = api.getProbeGeneration(HOST)

  // 一个更早发起的探测现在才回来 —— 它带着旧 generation
  const stale = api.commitProbeResult(
    HOST,
    genAfterNew - 1,
    {
      ips: ['203.0.113.1'],
      results: [{ ip: '203.0.113.1', okCount: 3, samples: 3, median: 999, best: 999, colo: 'LAX', excluded: null }],
      lastProbeAt: api.deps.now(),
      error: null,
    },
  )

  assert.equal(stale, false, '过期探测结果必须被拒绝')
  const entry = api.state().hosts.get(HOST)
  assert.equal(entry.results[0].ip, '203.0.113.9', 'hosts 应保留新探测结果')
  assert.equal(entry.results[0].median, 42)
})

test('场景 C2：同代探测正常提交', () => {
  setup()
  seed([{ ip: '203.0.113.1', median: 500 }])
  const gen = api.getProbeGeneration(HOST)

  const ok = api.commitProbeResult(HOST, gen, {
    ips: ['203.0.113.2'],
    results: [{ ip: '203.0.113.2', okCount: 3, samples: 3, median: 80, best: 80, colo: 'HKG', excluded: null }],
    lastProbeAt: api.deps.now(),
    error: null,
  })

  assert.equal(ok, true)
  assert.equal(api.state().hosts.get(HOST).results[0].ip, '203.0.113.2')
})

/* ============================================================
 * 场景 D：100 并发交错
 * ============================================================ */

test('场景 D：100 个并发交错 —— 旧请求不许改路由，新请求负责自愈', async () => {
  const { clock } = setup({ failThreshold: 2 })

  const IPS = ['203.0.113.1', '203.0.113.2', '203.0.113.3']
  seed(IPS.map((ip, i) => ({ ip, median: 100 * (i + 1) })))

  api.switchRoute(HOST, IPS[0], 'initial')

  // 100 个请求全部在「切换发生之前」出发，因此携带旧 generation
  const inflight = []
  for (let i = 0; i < 100; i += 1) {
    inflight.push({
      ip: IPS[i % 3],
      generation: api.getRouteGeneration(HOST),
      ok: i % 2 === 0,
      ttfbMs: 50 + (i % 40),
      error: { message: `err-${i}`, kind: 'error' },
    })
  }
  assert.equal(new Set(inflight.map((r) => r.generation)).size, 1, '这批请求应共享同一个旧 generation')

  // 1 号 IP 判死并切走（这两次用的是「当前」generation，有权切换）
  api.recordRequestFailure(HOST, IPS[0], { message: 'dead', kind: 'error' }, api.getRouteGeneration(HOST))
  api.recordRequestFailure(HOST, IPS[0], { message: 'dead', kind: 'error' }, api.getRouteGeneration(HOST))

  const routeAfterFailover = api.state().currentIp.get(HOST)
  const genAfterFailover = api.getRouteGeneration(HOST)
  assert.notEqual(routeAfterFailover, IPS[0], '1 号已判死，路由应已离开它')

  const switchesAfterFailover = api.state().switches.length

  // 交错完成所有在飞请求（全部是旧 generation）
  for (const r of inflight.sort(() => Math.random() - 0.5)) {
    if (r.ok) api.recordRequestSuccess(HOST, r.ip, { ttfbMs: r.ttfbMs, reused: false }, r.generation)
    else api.recordRequestFailure(HOST, r.ip, r.error, r.generation)
  }

  // 断言 1：路由没有被这批旧请求改动过
  assert.equal(api.statOf(HOST, IPS[0]).ok > 0, true, '旧 IP 的统计仍要更新')
  assert.equal(
    api.state().switches.length,
    switchesAfterFailover,
    '旧 generation 的请求一律不得产生新的切换记录',
  )

  // 断言 2：generation 不变（没有切换发生）
  assert.equal(api.getRouteGeneration(HOST), genAfterFailover, 'generation 不该因旧请求变化')

  // 断言 3：全部候选都被这批失败打进了冷却（这是正确行为 —— 统计反映事实）
  const cooling = IPS.filter((ip) => api.statOf(HOST, ip).penaltyUntil > clock.now())
  assert.ok(cooling.length >= 1, '至少一个 IP 进入冷却')

  // 断言 4：自愈 —— 下一个「新」请求（当前 generation）有权离开冷却节点
  const freshGen = api.getRouteGeneration(HOST)
  const currentNow = api.state().currentIp.get(HOST)
  const stillCooling = currentNow && api.statOf(HOST, currentNow).penaltyUntil > clock.now()
  if (stillCooling) {
    const next = api.chooseBest(HOST, currentNow)
    if (next) {
      api.switchRoute(HOST, next.ip, 'request:penalized')
      assert.notEqual(api.state().currentIp.get(HOST), currentNow, '新请求应能离开冷却节点')
      assert.ok(api.getRouteGeneration(HOST) > freshGen, '自愈切换应递增 generation')
    }
  }

  // 断言 5：不存在「因为成功回调而切换」的记录
  const successSwitches = api.state().switches.filter((s) => String(s.reason).startsWith('success'))
  assert.deepEqual(successSwitches, [], '成功回调不得产生任何切换记录')

  // 断言 6：generation 与切换次数始终一致
  assert.equal(api.getRouteGeneration(HOST), api.state().switches.length, 'generation 应等于实际切换次数')
})

/* ============================================================
 * 契约：switchRoute 是唯一改路由的入口
 * ============================================================ */

test('switchRoute 相同 IP 不递增 generation、不记切换', () => {
  setup()
  seed([{ ip: '203.0.113.1', median: 100 }])

  api.switchRoute(HOST, '203.0.113.1', 'initial')
  const gen = api.getRouteGeneration(HOST)
  const switches = api.state().switches.length

  api.switchRoute(HOST, '203.0.113.1', 'same')

  assert.equal(api.getRouteGeneration(HOST), gen, '切到同一个 IP 不算切换')
  assert.equal(api.state().switches.length, switches)
})

test('switchRoute 到 null（无可用候选）也递增 generation', () => {
  setup()
  seed([{ ip: '203.0.113.1', median: 100 }])
  api.switchRoute(HOST, '203.0.113.1', 'initial')
  const gen = api.getRouteGeneration(HOST)

  api.switchRoute(HOST, null, 'all-penalized')

  assert.equal(api.getRouteGeneration(HOST), gen + 1)
  assert.equal(api.state().currentIp.has(HOST), false)
})

test('getRouteGeneration 对未登记的 host 返回 0', () => {
  setup()
  assert.equal(api.getRouteGeneration('never-seen.test'), 0)
})

test('recordRequestSuccess 不改变任何 host 的 currentIp', () => {
  setup()
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 200 },
  ])
  api.switchRoute(HOST, '203.0.113.2', 'initial')

  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 30 }, api.getRouteGeneration(HOST))

  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', '成功回调绝不能改路由')
})

test('recordRequestSuccess 的 EWMA 语义保持（400→600、alpha 0.5 得 500）', () => {
  setup({ ewmaAlpha: 0.5 })
  seed([{ ip: '203.0.113.1', median: 200 }])

  // Issue #3 起 TTFB 分新连接/复用两路，这里固定走「新连接」
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 400, reused: false }, 0)
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 600, reused: false }, 0)

  const s = api.statOf(HOST, '203.0.113.1')
  assert.equal(s.ok, 2)
  assert.equal(s.metrics.freshTtfbEwmaMs, 500, 'EWMA 语义不变（400→600，alpha 0.5）')
})

test('多次真切换后 generation 等于切换次数', () => {
  setup()
  seed([
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 200 },
    { ip: '203.0.113.3', median: 300 },
  ])

  api.switchRoute(HOST, '203.0.113.1', 's1')
  api.switchRoute(HOST, '203.0.113.2', 's2')
  api.switchRoute(HOST, '203.0.113.3', 's3')

  assert.equal(api.getRouteGeneration(HOST), 3, '初选 + 两次切换 = 3 次递增')
})
