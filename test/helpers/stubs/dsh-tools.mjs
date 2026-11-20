/**
 * @deepseek-ai/dsh-tools 的最小桩
 *
 * 真实实现只做一件事：给工具定义套一层元数据壳并注册到 ctx.tools。
 * 插件对它的使用只有 `ctx.tools.register(defineTool({...}))`，
 * 所以这里原样返回入参就够了 —— 测试关心的是「注册了哪些工具、叫什么名字」，
 * 不是 DSH 内部怎么包装。
 */
export function defineTool(def) {
  return def
}

export default { defineTool }
