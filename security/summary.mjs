// reports/의 nuclei·tlsx·naabu 결과를 한 형식으로 모아 심각도 순으로 출력한다.
// high 이상이 있으면 종료 코드 1.
//   node summary.mjs <reports 디렉터리>
// ALLOWED_PORTS(쉼표 구분)에 없는 열린 포트는 low로 보고한다.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2] ?? 'reports';
const order = ['critical', 'high', 'medium', 'low', 'info'];
const allowedPorts = new Set((process.env.ALLOWED_PORTS ?? '').split(',').filter(Boolean).map(Number));

const readJsonl = (file) =>
  existsSync(join(dir, file))
    ? readFileSync(join(dir, file), 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l))
    : [];

const findings = [];
const add = (severity, id, target) => findings.push({ severity, id, target });

for (const file of readdirSync(dir).filter((f) => /^nuclei-.*\.jsonl$/.test(f))) {
  for (const r of readJsonl(file)) add(r.info.severity, r['template-id'], r['matched-at']);
}

for (const r of readJsonl('tlsx.jsonl')) {
  const target = `${r.host}:${r.port}`;
  if (!r.probe_status) continue;
  if (r.expired) add('high', 'tls-expired-cert', target);
  if (r.self_signed) add('medium', 'tls-self-signed-cert', target);
  if (r.mismatched) add('medium', 'tls-hostname-mismatch', target);
  if (['ssl30', 'tls10', 'tls11'].includes(r.tls_version)) add('medium', `tls-deprecated-${r.tls_version}`, target);
}

for (const r of readJsonl('naabu.jsonl')) {
  if (!allowedPorts.has(r.port)) add('low', 'unexpected-open-port', `${r.host ?? r.ip}:${r.port}`);
}

// nuclei는 추출기마다 결과를 한 줄씩 남기므로 같은 대상·ID는 하나로 합친다.
const seen = new Set();
const rows = findings
  .filter((f) => !seen.has(f.id + f.target) && seen.add(f.id + f.target))
  .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

for (const f of rows) console.log(`${f.severity.padEnd(8)} ${f.id}  ${f.target}`);
if (!rows.length) console.log('발견 없음');
process.exit(rows.some((f) => order.indexOf(f.severity) <= 1) ? 1 : 0);
