/**
 * switch-policy.mjs — 切换迟滞策略（Issue #10 阶段 1）
 *
 * 现状（改造前）只有一条判据：
 *
 *   prevScore > best.score * 1.3      // 单轮快 30% 就切
 *
 * 三个缺口：
 *   1. **不看样本量**。两条线路各只探过一次就比大小，纯属噪声决策。
 *   2. **不看连续性**。一次探测抖动就能把线路换掉，下一轮又换回来。
 *   3. **不看驻留时间**。刚切过去 3 秒又切走，连接池反复排空/重建。
 *
 * 关键区分（方案 §3.2）：**硬故障切换不受任何迟滞约束**。
 * 当前线路一旦确认不可用（network/timeout/冷却），立刻切走 ——
 * 让它继续服务只会把错误暴露给真实请求。
 */

/** 切换原因分类 */
export const SWITCH_HARD_FAIL = 'hard_fail'
export const SWITCH_PERFORMANCE = 'performance'
export const SWITCH_NONE = 'none'

/**
 * 样本是否足以做性能比较。
 *
 * 单条样本的「中位数」就是那条样本本身，比较两个单样本等于比较两次运气。
 * 门槛按两侧取小 —— 新候选样本少时不应该被强行推上台。
 */
export function hasEnoughSamples(prevSamples, bestSamples, minSamples) {
  const need = Math.max(1, Number(minSamples) || 1)
  const p = Number(prevSamples) || 0
  const b = Number(bestSamples) || 0
  return p >= need && b >= need
}

/**
 * 判断一次探测后的切换决策。
 *
 * @param {object} input
 * @param {string|null} input.prevIp
 * @param {number} input.prevScore          当前线路分数（Infinity = 不可用）
 * @param {string|null} input.bestIp
 * @param {number} input.bestScore          最优候选分数
 * @param {string} input.prevHealth         healthy | cooling | half_open
 * @param {number} input.roundsBetter       之前累计的「连续更优」轮次
 * @param {number} input.lastSwitchAt       上次切换时刻（0 = 从未）
 * @param {number} input.now
 * @param {number} input.prevSamples        当前线路的有效样本数
 * @param {number} input.bestSamples        最优候选的有效样本数
 * @param {object} input.cfg  { minImprovementRatio, consecutiveBetterRounds, minDwellTimeMs, minSamples }
 * @returns {{switch: boolean, kind: string, reason: string, roundsBetter: number,
 *            improvementRatio: number|null, blockedBy: string|null}}
 */
export function decideSwitch(input) {
  const {
    prevIp = null, prevScore = Infinity, bestIp = null, bestScore = Infinity,
    prevHealth = 'healthy', roundsBetter = 0, lastSwitchAt = 0, now = 0,
    prevSamples = 0, bestSamples = 0, cfg = {},
  } = input

  const no = (blockedBy, reason, rounds = 0) => ({
    switch: false, kind: SWITCH_NONE, reason, roundsBetter: rounds,
    improvementRatio: null, blockedBy,
  })

  // ---- 1. 没有候选：不切 ----
  if (!bestIp) return no('no_candidate', '无可用候选')

  // ---- 2. 已经是最优：不切 ----
  if (prevIp === bestIp) return no('already_best', '当前已是最优', 0)

  // ---- 3. 没有当前线路：直接上 ----
  if (!prevIp) {
    return {
      switch: true, kind: SWITCH_HARD_FAIL, reason: '当前无线路',
      roundsBetter: 0, improvementRatio: null, blockedBy: null,
    }
  }

  // ---- 4. 硬故障：当前线路不可用（冷却 / half_open / 无分数）→ 立即切 ----
  //
  // **不受任何迟滞约束**（方案 §3.2）。让它继续服务只会把错误
  // 暴露给真实请求。驻留时间、样本量、改善幅度全都不该拦住这一步。
  if (prevHealth !== 'healthy' || !Number.isFinite(prevScore)) {
    return {
      switch: true, kind: SWITCH_HARD_FAIL,
      reason: prevHealth !== 'healthy' ? `当前线路健康状态 ${prevHealth}` : '当前线路不可评分',
      roundsBetter: 0, improvementRatio: null, blockedBy: null,
    }
  }

  // ---- 5. 性能切换：逐条过闸 ----
  const minRatio = Math.max(0, Number(cfg.minImprovementRatio) || 0)
  const needRounds = Math.max(1, Number(cfg.consecutiveBetterRounds) || 1)
  const minDwell = Math.max(0, Number(cfg.minDwellTimeMs) || 0)

  // 5a. 最优候选本身必须可用
  if (!Number.isFinite(bestScore) || bestScore <= 0) {
    return no('best_unscorable', '最优候选不可评分', 0)
  }

  // 5b. 样本量
  if (!hasEnoughSamples(prevSamples, bestSamples, cfg.minSamples)) {
    return no('insufficient_samples',
      `样本不足（当前 ${prevSamples} / 最优 ${bestSamples}，需 ${cfg.minSamples || 1}）`, 0)
  }

  // 5c. 改善幅度（best 必须比 prev 快 minRatio 以上）
  const ratio = (prevScore - bestScore) / prevScore
  if (ratio < minRatio) {
    return {
      ...no('insufficient_improvement',
        `改善 ${(ratio * 100).toFixed(1)}% < 门槛 ${(minRatio * 100).toFixed(1)}%`, 0),
      improvementRatio: ratio,
    }
  }

  // 5d. 连续更优轮次（这一轮算一轮）
  const nextRounds = roundsBetter + 1
  if (nextRounds < needRounds) {
    return {
      ...no('need_more_rounds', `连续更优 ${nextRounds}/${needRounds} 轮`, nextRounds),
      improvementRatio: ratio,
    }
  }

  // 5e. 最短驻留时间（最后一道，避免刚切完又切走）
  if (lastSwitchAt > 0 && now - lastSwitchAt < minDwell) {
    return {
      ...no('min_dwell', `驻留 ${now - lastSwitchAt}ms < ${minDwell}ms`, nextRounds),
      improvementRatio: ratio,
    }
  }

  return {
    switch: true, kind: SWITCH_PERFORMANCE,
    reason: `快 ${(ratio * 100).toFixed(1)}%，连续 ${nextRounds} 轮更优`,
    roundsBetter: 0, improvementRatio: ratio, blockedBy: null,
  }
}
