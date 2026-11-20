/**
 * fake-clock.mjs — 可控时钟
 *
 * 插件的冷却、驻留、探测间隔全部基于 deps.now()。
 * 测试里直接推进这个时钟，就能在毫秒内验证「冷却 60 秒后恢复」之类的行为，
 * 不用真的 sleep。
 */
export function createClock(startAt = 1_700_000_000_000) {
  let t = startAt
  return {
    now: () => t,
    advance(ms) {
      if (!Number.isFinite(ms) || ms < 0) throw new Error('advance 需要非负毫秒数')
      t += ms
      return t
    },
    set(v) { t = v; return t },
    get current() { return t },
  }
}
