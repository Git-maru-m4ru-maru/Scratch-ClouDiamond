// vmharness.js -- 本物の Scratch VM (scratch-vm) でプロジェクトを実行するテスト用ハーネス
//
//   node vmharness.js run    project.sb3 [timeoutSec]  -> 変数/リストを JSON 1 行で出力(変数 done が 1 になるまで待つ)
//   node vmharness.js bridge project.sb3 [timeoutSec]  -> stdin/stdout の JSON 行でクラウド変数・ask・say を中継
//
// bridge の入力(stdin, 1 行 1 JSON):
//   {"t":"set","name":"☁ S2C_HDR","value":"..."}   クラウド変数をサーバー側から書き込む
//   {"t":"answer","text":"..."}                     ask への回答
//   {"t":"dump"} / {"t":"quit"}
// 出力(stdout):
//   {"t":"started"} / {"t":"cloud","name":..,"value":..} / {"t":"say","text":..} / {"t":"ask","text":..}
//   {"t":"dump","vars":{..},"lists":{..}} / {"t":"timeout"}
//
// scratch-vm の場所は環境変数 CLOUDIAMOND_SCRATCH_VM(= node_modules ディレクトリ)で指定する。
const path = require('path');
const fs = require('fs');
const readline = require('readline');

const root = process.env.CLOUDIAMOND_SCRATCH_VM || path.join(__dirname, 'node_modules');
const VM = require(path.join(root, 'scratch-vm'));

const [mode, file, tmo] = process.argv.slice(2);
const timeoutMs = (parseFloat(tmo) || 120) * 1000;
console.warn = () => {};                       // "No storage module present" を黙らせる

function dump(vm) {
  const out = { vars: {}, lists: {} };
  for (const t of vm.runtime.targets) {
    for (const v of Object.values(t.variables)) {
      if (v.type === 'list') out.lists[v.name] = v.value; else out.vars[v.name] = v.value;
    }
  }
  return out;
}

(async () => {
  const vm = new VM();
  await vm.loadProject(fs.readFileSync(file));
  const t0 = Date.now();

  if (mode === 'run') {
    vm.start(); vm.greenFlag();
    for (;;) {
      await new Promise(r => setTimeout(r, 50));
      const d = dump(vm);
      if (d.vars.done == 1 || Date.now() - t0 > timeoutMs) {
        d.elapsed = (Date.now() - t0) / 1000; d.timedOut = d.vars.done != 1;
        process.stdout.write(JSON.stringify(d) + '\n'); process.exit(0);
      }
    }
  }

  if (mode === 'bridge') {
    const emit = o => process.stdout.write(JSON.stringify(o) + '\n');
    vm.runtime.ioDevices.cloud.setProvider({
      updateVariable: (name, value) => emit({ t: 'cloud', name, value: String(value) }),
      createVariable() {}, renameVariable() {}, deleteVariable() {}, requestCloseConnection() {},
    });
    vm.runtime.ioDevices.cloud.setStage(vm.runtime.getTargetForStage());
    vm.runtime.on('SAY', (target, type, text) => { if (text !== '') emit({ t: 'say', text: String(text) }); });
    // 表示中のスプライトの ask は、質問文が吹き出し(SAY)で出て QUESTION は空文字になる(実物の Scratch も同じ)。
    // 空文字も「回答を待っている」合図として通知する。null は質問の終了。
    vm.runtime.on('QUESTION', q => { if (q !== null) emit({ t: 'ask', text: String(q) }); });
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', line => {
      const m = JSON.parse(line);
      if (m.t === 'set') vm.runtime.ioDevices.cloud.updateCloudVariable({ name: m.name, value: m.value });
      else if (m.t === 'answer') vm.runtime.emit('ANSWER', m.text);
      else if (m.t === 'dump') emit({ t: 'dump', ...dump(vm) });
      else if (m.t === 'quit') process.exit(0);
    });
    vm.start(); vm.greenFlag();
    emit({ t: 'started' });
    setTimeout(() => { emit({ t: 'timeout' }); process.exit(2); }, timeoutMs);
    return;
  }
  console.error('unknown mode'); process.exit(1);
})().catch(e => { console.error('ERR', (e && e.stack) || e); process.exit(1); });
