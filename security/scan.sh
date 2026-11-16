#!/usr/bin/env bash
# ProjectDiscovery 도구(httpx, nuclei)로 로컬 MCP 서버와 인가 서버를 검사한다.
# 서버를 먼저 띄운 뒤 실행한다. 결과는 security/reports/에 남는다.
#
#   MCP_URL=http://localhost:3000/mcp AUTH_URL=http://localhost:4000 security/scan.sh
#
# high 이상이 하나라도 나오면 종료 코드 1.
set -euo pipefail

cd "$(dirname "$0")"

# 검사 대상 주소. nuclei는 Windows에서 localhost를 못 찾으므로 127.0.0.1을 쓴다.
MCP_URL=${MCP_URL:-http://127.0.0.1:3000/mcp}
AUTH_URL=${AUTH_URL:-http://127.0.0.1:4000}
# 위조 토큰에 넣을 iss, aud. 서버의 AUTH_ISSUER, MCP_RESOURCE_URL과 같아야 한다.
ISSUER=${ISSUER:-http://localhost:4000}
AUDIENCE=${AUDIENCE:-http://localhost:3000/mcp}
# 커뮤니티 템플릿 검사(nuclei-templates)도 돌릴지. 느리므로 기본은 끈다.
COMMUNITY=${COMMUNITY:-0}
REPORTS=reports

# 바이너리가 없으면 공식 Docker 이미지로 실행한다(Linux 전용: --network host로 localhost에 붙는다).
pd() { docker run --rm --network host -v "$PWD:/work" -w /work "projectdiscovery/$1:$2" "${@:3}"; }
command -v httpx >/dev/null || httpx() { pd httpx "${HTTPX_TAG:-latest}" "$@"; }
command -v nuclei >/dev/null || nuclei() { pd nuclei "${NUCLEI_TAG:-latest}" "$@"; }

mkdir -p "$REPORTS"
printf '%s\n%s\n' "$MCP_URL" "$AUTH_URL" > "$REPORTS/targets.txt"

echo "== httpx: 응답·기술 스택 확인"
httpx -l "$REPORTS/targets.txt" -silent -status-code -title -tech-detect -no-color -o "$REPORTS/httpx.txt"

echo "== nuclei: 템플릿 문법 검사"
nuclei -validate -t templates -silent -duc

echo "== nuclei: 프로젝트 템플릿"
# 로컬 서버라 속도 제한은 낮게 두지 않는다. 운영 대상이면 -rl을 낮춘다.
nuclei -l "$REPORTS/targets.txt" -t templates \
  -var issuer="$ISSUER" -var audience="$AUDIENCE" \
  -jsonl -o "$REPORTS/nuclei-custom.jsonl" \
  -markdown-export "$REPORTS/markdown" \
  -no-color -silent -duc >/dev/null

if [ "$COMMUNITY" = 1 ]; then
  echo "== nuclei: 커뮤니티 템플릿 (misconfig, exposure)"
  nuclei -l "$REPORTS/targets.txt" -tags misconfig,exposure,token \
    -severity low,medium,high,critical \
    -jsonl -o "$REPORTS/nuclei-community.jsonl" \
    -no-color -silent -duc >/dev/null
fi

echo "== 요약"
# 결과 JSONL을 읽어 심각도 순으로 출력하고, high 이상이면 1로 끝낸다.
node -e '
const fs = require("fs");
const order = ["critical", "high", "medium", "low", "info"];
let rows = process.argv.slice(1).filter(fs.existsSync)
  .flatMap(f => fs.readFileSync(f, "utf8").split(/\r?\n/).filter(Boolean).map(JSON.parse));
const seen = new Set();
rows = rows.filter(r => { const k = r["template-id"] + r["matched-at"]; return !seen.has(k) && seen.add(k); });
rows.sort((a, b) => order.indexOf(a.info.severity) - order.indexOf(b.info.severity));
for (const r of rows) console.log(`${r.info.severity.padEnd(8)} ${r["template-id"]}  ${r["matched-at"]}`);
if (!rows.length) console.log("발견 없음");
process.exit(rows.some(r => order.indexOf(r.info.severity) <= 1) ? 1 : 0);
' "$REPORTS"/nuclei-*.jsonl
