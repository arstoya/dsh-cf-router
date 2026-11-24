/**
 * contract/index.mjs — 契约层统一出口（Issue #26 / A2）
 *
 * 两种入口（Forward / Reverse）与 Core 之间唯一的共享词汇表。
 *
 * ## 这一层刻意不知道的事
 *
 * 它**不 import `node:http`**，也不 import 任何 Adapter。理由：
 * 一旦契约层知道 HTTP 入口长什么样，下游就会开始依赖入口专有对象
 * （`req` / `res` / `socket`），两种入口就无法共用同一套 Core。
 *
 * 有测试静态检查这一点（`test/contract/isolation.test.js`）。
 *
 * @module contract
 */

export {
  ProxyError,
  TargetDenied, ClientUnauthorized, DnsFailure, ConnectFailure,
  TlsFailure, UpstreamTimeout, ClientCancelled, StreamFailure, RetryNotAllowed,
  ERROR_CODES, errorFromCode, isProxyError,
} from './errors.mjs'

export {
  makeRequestContext, isRequestContext, REQUEST_MODES,
} from './request-context.mjs'

export {
  makeUpstream, makeUpstreamGroup, makeProxyClient, makeRetryPolicy,
  validateGroupReferences,
  UPSTREAM_PROTOCOLS, ROUTING_MODES,
} from './upstream.mjs'
