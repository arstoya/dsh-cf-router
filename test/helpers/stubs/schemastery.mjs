/**
 * @deepseek-ai/schemastery 的最小桩
 *
 * 插件只用它做两件事：声明 Config 的字段默认值，以及 apply() 时拿到填好默认值的配置对象。
 *
 * ⚠ 关键：`.volatile()` 的语义必须与生产一致
 *
 * 生产（@deepseek-ai/schemastery/lib/index.mjs:273）：
 *   return [createVolatile(value), adapted]
 *   createVolatile（@deepseek-ai/cosmokit/lib/index.js:102）返回
 *   Object.freeze({ get: () => current, [write]: fn })
 *
 * 也就是说 volatile 字段拿到的是**带稳定身份的引用对象**，不是普通值：
 *   1. 引用身份稳定（同一个字段多次访问是同一个对象）
 *   2. .get() 返回**当前**保存的值
 *   3. 写入会更新引用内部的值
 *   4. 外壳被冻结（不能加/删属性）
 *
 * 若桩里只返回普通字符串，插件代码里那条
 *   `typeof raw.get === 'function' ? raw.get() : raw`
 * 会走 else 分支 —— 测试通过但测的是另一条路径。这是 Issue #18 的前置缺陷。
 */

/** 构造与生产同构的 volatile 引用 */
export function makeVolatile(initialValue) {
  let current = initialValue
  const ref = {
    /** 返回当前保存的值 */
    get: () => current,
    /** 更新内部值并返回新值。生产用 Symbol 作为 write 键，这里暴露方法以便测试驱动 */
    set: (next) => { current = next; return current },
    /** 便于断言"这是一个 volatile 引用" */
    [Symbol.for('dsh-cf-router.volatile')]: true,
  }
  return Object.freeze(ref)
}

/** 判定是否为 volatile 引用 */
export function isVolatileRef(value) {
  return Boolean(
    value
    && typeof value === 'object'
    && typeof value.get === 'function'
    && typeof value.set === 'function',
  )
}

function makeSchema(kind) {
  const node = function (input) {
    return node._build(input)
  }
  node._kind = kind
  node._default = undefined
  node._desc = ''
  node._isVolatile = false
  node.description = (text) => { node._desc = text; return node }
  node.default = (value) => { node._default = value; return node }
  node.volatile = () => { node._isVolatile = true; return node }
  node.optional = () => node
  node._build = (input) => {
    const value = input === undefined ? node._default : input
    // 与生产一致：volatile 字段产出引用对象，其余产出普通值
    return node._isVolatile ? makeVolatile(value) : value
  }
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
