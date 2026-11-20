/**
 * stub-register.mjs — 把 @deepseek-ai/* 映射到本地桩
 *
 * lib/index.js 顶层 import 了宿主的 `@deepseek-ai/dsh-tools` 与
 * `@deepseek-ai/schemastery`。这两个包只存在于 DSH 安装目录的
 * resources/app/dsh/node_modules 里，而且会连锁拉进 @deepseek-ai/cordis 等
 * 一大串宿主内部包 —— 测试不该依赖它们，也不该去拷那堆东西。
 *
 * 所以用 Node 内置的模块钩子把它们重定向到 test/helpers/stubs/ 下的最小实现。
 * 生产加载路径完全不受影响（这个文件只在 npm test 时通过 --import 加载）。
 */
import { registerHooks } from 'node:module'
import { pathToFileURL } from 'node:url'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))

// 测试模式：让 lib 的 statePath 兜底到临时目录，绝不允许落到真实的 $DSH_HOME。
// （踩过的坑：一次 setRoutingMode 把线上运行插件的状态文件写成了 direct）
process.env.CFR_TEST_MODE = '1'

const MAP = {
  '@deepseek-ai/dsh-tools': join(HERE, 'stubs', 'dsh-tools.mjs'),
  '@deepseek-ai/schemastery': join(HERE, 'stubs', 'schemastery.mjs'),
}

registerHooks({
  resolve(specifier, context, nextResolve) {
    const hit = MAP[specifier]
    if (hit) return { url: pathToFileURL(hit).href, shortCircuit: true }
    return nextResolve(specifier, context)
  },
})
