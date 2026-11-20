/**
 * @deepseek-ai/schemastery 的最小桩
 *
 * 插件只用它做两件事：声明 Config 的字段默认值，以及 apply() 时拿到填好默认值的配置对象。
 * 真实 schemastery 是函数式 schema（`.default()` 返回自身、Config(input) 返回合并后的值），
 * 这里实现同样语义的最小子集，够跑通测试又不引入宿主依赖。
 *
 * ⚠ 这不是完整实现：不校验类型、不处理嵌套 schema、不支持 transform。
 * 一旦插件用上更多 schema 能力，这里的 stub 就要跟着长。
 */

function makeSchema(kind) {
  const node = function (input) {
    return node._build(input)
  }
  node._kind = kind
  node._default = undefined
  node._desc = ''
  node.description = (text) => { node._desc = text; return node }
  node.default = (value) => { node._default = value; return node }
  node.volatile = () => node
  node.optional = () => node
  node._build = (input) => (input === undefined ? node._default : input)
  return node
}

function objectSchema(shape) {
  const node = function (input) {
    const src = input && typeof input === 'object' ? input : {}
    const out = {}
    for (const [key, field] of Object.entries(shape)) {
      const provided = Object.prototype.hasOwnProperty.call(src, key) ? src[key] : undefined
      out[key] = field._build(provided)
    }
    // 允许传入未声明的键（真实 schemastery 会剔除，这里保留以便测试观察）
    return out
  }
  node._kind = 'object'
  node._shape = shape
  node.description = () => node
  node.default = () => node
  node._build = (input) => node(input)
  return node
}

const z = {
  object: (shape) => objectSchema(shape),
  array: () => makeSchema('array'),
  string: () => makeSchema('string'),
  number: () => makeSchema('number'),
  boolean: () => makeSchema('boolean'),
  any: () => makeSchema('any'),
}

export default z
export { z }
