#!/usr/bin/env bash
# ProjectDiscovery 도구(httpx, nuclei, tlsx, naabu)로 로컬 MCP 서버와 인가 서버를 검사한다.
# 서버를 먼저 띄운 뒤 실행한다. 결과는 security/reports/에 남는다.
#
#   security/scan.sh
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
# 0이면 interactsh(외부 OOB 서버)를 쓰지 않는다. oauth-dcr-ssrf 템플릿은 이때 결과가 없다.
OAST=${OAST:-1}
# 커뮤니티 템플릿 검사(nuclei-templates)도 돌릴지. 느리므로 기본은 끈다.
COMMUNITY=${COMMUNITY:-0}
# tlsx로 볼 https 대상(host:port, 쉼표 구분). 로컬은 http라 기본은 비어 있다.
TLS_TARGETS=${TLS_TARGETS:-}
# naabu로 열린 포트를 볼 호스트와 범위. 허용 목록 밖 포트는 low로 보고한다.
PORT_HOST=${PORT_HOST:-}
PORT_RANGE=${PORT_RANGE:-1-10000}
export ALLOWED_PORTS=${ALLOWED_PORTS:-3000,4000}
REPORTS=reports/scan

# 바이너리가 없으면 공식 Docker 이미지로 실행한다(Linux 전용: --network host로 localhost에 붙는다).
pd() { docker run --rm --network host -v "$PWD:/work" -w /work "projectdiscovery/$1:$2" "${@:3}"; }
command -v httpx >/dev/null || httpx() { pd httpx "${HTTPX_TAG:-latest}" "$@"; }
command -v nuclei >/dev/null || nuclei() { pd nuclei "${NUCLEI_TAG:-latest}" "$@"; }
command -v tlsx >/dev/null || tlsx() { pd tlsx "${TLSX_TAG:-latest}" "$@"; }
command -v naabu >/dev/null || naabu() { pd naabu "${NAABU_TAG:-latest}" "$@"; }

rm -rf "$REPORTS"
mkdir -p "$REPORTS"
printf '%s\n%s\n' "$MCP_URL" "$AUTH_URL" > "$REPORTS/targets.txt"

echo "== httpx: 응답·기술 스택 확인"
httpx -l "$REPORTS/targets.txt" -silent -status-code -title -tech-detect -no-color -o "$REPORTS/httpx.txt"

echo "== nuclei: 템플릿 문법 검사"
nuclei -validate -t templates -silent -duc

echo "== nuclei: 프로젝트 템플릿"
# 로컬 서버라 속도 제한은 낮게 두지 않는다. 운영 대상이면 -rl을 낮춘다.
oast_flag=()
[ "$OAST" = 1 ] || oast_flag=(-ni)
nuclei -l "$REPORTS/targets.txt" -t templates "${oast_flag[@]}" \
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

if [ -n "$TLS_TARGETS" ]; then
  echo "== tlsx: TLS 버전·인증서"
  tlsx -u "$TLS_TARGETS" -tls-version -cipher -expired -self-signed -mismatched \
    -json -o "$REPORTS/tlsx.jsonl" -silent -no-color >/dev/null
fi

if [ -n "$PORT_HOST" ]; then
  echo "== naabu: 열린 포트 (허용: $ALLOWED_PORTS)"
  # connect 스캔이라 root 권한이 없어도 된다.
  naabu -host "$PORT_HOST" -p "$PORT_RANGE" -s c \
    -json -o "$REPORTS/naabu.jsonl" -silent -no-color >/dev/null
fi

echo "== 요약"
node summary.mjs "$REPORTS"
