#!/usr/bin/env node
/**
 * doctor.mjs — 插件自检（只读，不启动代理、不发网络请求）
 *
 * 回答：**这个包作为 DSH 插件能不能装、能不能挂上去？**
 *
 * 它检查的是「包本身的完整性」与「宿主侧前置条件」，不是运行时性能：
 *   FAIL  装不上或挂上就崩（入口缺失、语法错误、peer 依赖解析不到、patch 指向不存在的文件）
 *   WARN  能装但可能不工作（DSH_HOME 未定位、端口被占、engines 与当前 DSH 不匹配）
 *   INFO  环境事实
 *
 * 用法：
 *   node scripts/doctor.mjs
 *   node scripts/doctor.mjs --json
 *   node scripts/doctor.mjs --dsh-home /path/to/dsh-home
 *
 * 退出码：0 无 FAIL / 2 有 FAIL
 */
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const argv = process.argv.slice(2);
const AS_JSON = argv.includes('--json');
const opt = (n) => {
  const i = argv.indexOf(n);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null;
};

const results = [];
const add = (level, name, detail) => results.push({ level, name, detail });
const exists = (p) => { try { return existsSync(p); } catch { return false; } };
const firstExisting = (...c) => c.filter(Boolean).find((p) => exists(p)) || null;

/* ---------- 1. 包完整性 ---------- */

let pkg = null;
try {
  pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  add('PASS', 'package.json 可解析', `${pkg.name}@${pkg.version}`);
} catch (e) {
  add('FAIL', 'package.json 可解析', String(e.message || e));
}

if (pkg) {
  const entry = pkg.main || './lib/index.js';
  if (exists(join(ROOT, entry))) add('PASS', '入口文件存在', entry);
  else add('FAIL', '入口文件存在', `${entry} 不存在 —— 挂载时 import 会直接失败`);

  for (const [name, target] of Object.entries(pkg.exports || {})) {
    const rel = typeof target === 'string' ? target : target?.import || target?.default;
    if (!rel) continue;
    if (exists(join(ROOT, rel))) add('PASS', `exports${name === '.' ? '' : ' ' + name}`, rel);
    else add('FAIL', `exports${name === '.' ? '' : ' ' + name}`, `${rel} 不存在`);
  }

  const patchRel = pkg.dsh?.bundle?.patch;
  if (patchRel) {
    if (exists(join(ROOT, patchRel))) {
      add('PASS', 'bundle patch 存在', patchRel);
      // 极简 YAML 结构检查：顶层必须是 `- insert:` 列表
      const txt = readFileSync(join(ROOT, patchRel), 'utf8');
      if (/^- insert:/m.test(txt)) add('PASS', 'bundle patch 结构', '顶层 - insert: 列表');
      else add('FAIL', 'bundle patch 结构', '没找到顶层 `- insert:`，Loader 会解析成别的东西或报错');
      if (/\t/.test(txt)) add('WARN', 'bundle patch 缩进', '含 Tab —— YAML 不允许 Tab 缩进');
      else add('PASS', 'bundle patch 缩进', '无 Tab');
    } else {
      add('FAIL', 'bundle patch 存在', `${patchRel} 不存在`);
    }
  } else {
    add('WARN', 'bundle patch', 'dsh.bundle.patch 未声明 —— 只能手工在 profile patch 里挂');
  }

  const engines = pkg.dsh?.engines?.dsh;
  if (engines) add('INFO', 'engines.dsh', engines);
  else add('WARN', 'engines.dsh', '未声明 —— 装到不兼容版本上不会被提前拦下');

  if (pkg.peerDependencies?.['@deepseek-ai/dsh-tools']) add('INFO', 'peer 依赖声明', Object.keys(pkg.peerDependencies).join(', '));
}

/* ---------- 2. 语法 ---------- */

const entryPath = pkg ? join(ROOT, pkg.main || './lib/index.js') : join(ROOT, 'lib/index.js');
if (exists(entryPath)) {
  try {
    execFileSync(process.execPath, ['--check', entryPath], { stdio: 'pipe', encoding: 'utf8' });
    add('PASS', '入口语法', 'node --check 通过');
  } catch (e) {
    add('FAIL', '入口语法', ((e.stdout || '') + (e.stderr || '')).trim().split('\n').slice(0, 3).join(' | '));
  }

  // 静态看导出面：有 name / Config / apply 才是一个能被 Loader 挂的插件
  const src = readFileSync(entryPath, 'utf8');
  for (const [label, re] of [
    ['导出 name', /^export const name\s*=/m],
    ['导出 Config', /^export const Config\s*=/m],
    ['导出 apply', /^export function apply\(/m],
  ]) {
    if (re.test(src)) add('PASS', label, '存在');
    else add('FAIL', label, '缺失 —— Loader 挂不上这个插件');
  }
  const toolCount = (src.match(/ctx\.tools\.register\(/g) || []).length;
  add(toolCount ? 'PASS' : 'WARN', '注册的工具数', String(toolCount));
}

/* ---------- 3. 宿主前置条件 ---------- */

const dshHome = opt('--dsh-home') || firstExisting(process.env.DSH_HOME, join(homedir(), '.dsh-home'), join(homedir(), 'dsh-home'), '/dsh-home', 'D:/dsh-home');
if (dshHome) add('PASS', 'DSH_HOME', dshHome);
else add('WARN', 'DSH_HOME', '未定位 —— 运行时 stateFile 会落到 cwd；设 DSH_HOME 或在 profile 里显式配 stateFile');

// peer 依赖：必须能从宿主解析。这里只做「能不能找到」的判断，不 import（会触发副作用）
const candidates = [
  dshHome ? join(dshHome, '..', 'app', 'dsh', 'node_modules') : null,
  dshHome ? join(dshHome, 'profiles') : null,
  '/opt/DeepSeek Harness/resources/app/dsh/node_modules',
  'D:/Deepseek Harness/resources/app/dsh/node_modules',
].filter(Boolean);
const dshToolsHit = candidates.find((c) => exists(join(c, '@deepseek-ai', 'dsh-tools')) || exists(join(c, '@deepseek-ai')));
if (dshToolsHit) add('PASS', '宿主 @deepseek-ai/*', dshToolsHit);
else add('WARN', '宿主 @deepseek-ai/*', '未定位到宿主 node_modules —— 装进 profile 后由宿主解析，通常无需处理');

/* ---------- 4. 端口占用（只测，不监听） ---------- */

let port = 8787;
try {
  const patchTxt = readFileSync(join(ROOT, pkg?.dsh?.bundle?.patch || 'cordis.patch.yml'), 'utf8');
  const m = /listenPort:\s*(\d+)/.exec(patchTxt);
  if (m) port = Number(m[1]);
} catch { /* 用默认 */ }

await new Promise((done) => {
  const sock = net.connect({ host: '127.0.0.1', port });
  const finish = (taken) => {
    try { sock.destroy(); } catch { /* ignore */ }
    if (taken) add('WARN', `端口 ${port}`, '已被占用 —— 可能本插件已在跑（正常），或与别的服务冲突');
    else add('PASS', `端口 ${port}`, '空闲');
    done();
  };
  sock.setTimeout(1500);
  sock.once('connect', () => finish(true));
  sock.once('timeout', () => finish(false));
  sock.once('error', () => finish(false));   // ECONNREFUSED = 空闲
});

/* ---------- 输出 ---------- */

const fails = results.filter((r) => r.level === 'FAIL');
const warns = results.filter((r) => r.level === 'WARN');

if (AS_JSON) {
  console.log(JSON.stringify({ ok: fails.length === 0, fails: fails.length, warns: warns.length, results }, null, 2));
  process.exit(fails.length ? 2 : 0);
}

const mark = { PASS: '✓', WARN: '!', FAIL: '✗', INFO: '·' };
const w = Math.max(...results.map((r) => r.name.length), 8);
console.log('dsh-cf-router 插件自检');
console.log(`  包目录  ${ROOT}`);
console.log('');
for (const r of results) console.log(`  ${mark[r.level]} ${r.name.padEnd(w)}  ${r.detail}`);
console.log('');
console.log(`结果：FAIL ${fails.length} · WARN ${warns.length} · 共 ${results.length} 项`);
if (fails.length) {
  console.log('未通过。按 ✗ 逐条修，修完重跑：node scripts/doctor.mjs');
  process.exit(2);
}
console.log(warns.length ? '可以安装，WARN 不影响挂载。' : '全绿，可以安装。');
process.exit(0);
