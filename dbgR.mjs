import http from 'node:http'
import * as mod from './lib/index.js'
import { startHttpsUpstream } from './test/fixtures/https-server.js'
import { freePort } from './test/helpers/deferred.mjs'
const api=mod.__testApi, HOST='localhost', IP='127.0.0.1'
const up = await startHttpsUpstream({ status: 200, body: 'z'.repeat(20000), abortMidBody: true })
const port = await freePort()
api.reset()
api.configure({targets:[HOST],discoverEnabled:false,allowPrivateTargets:true,listenHost:'127.0.0.1',
  listenPort:port,adminToken:'t',adminRateLimit:9999,probeSamples:1,probeTimeoutMs:1500,
  upstreamTimeoutMs:20000,firstByteTimeoutMs:5000,failThreshold:2,stateFile:process.env.TEMP+'/r.json'})
api.deps.upstreamPort=up.port; api.deps.tlsOptions={ca:up.cert}; api.deps.resolve4=(h,cb)=>cb(null,['127.0.0.1'])
const srv=api.createProxy(); await new Promise(r=>srv.once('listening',r))
await api.refreshHost(HOST); await new Promise(r=>setTimeout(r,150))
const before = api.statOf(HOST,IP).fail
await new Promise(res=>{const q=http.request({host:'127.0.0.1',port,path:'/x'},(x)=>{x.resume();x.on('end',res);x.on('error',()=>res())});q.on('error',()=>res());q.end()})
await new Promise(r=>setTimeout(r,1500))
console.log(`abortMidBody: fail ${before} → ${api.statOf(HOST,IP).fail}`)
api.closeProxy(); await up.close(); mod.__resetForTest(); process.exit(0)
