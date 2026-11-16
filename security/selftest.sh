#!/usr/bin/env bash
# 일부러 취약한 서버(fixtures/vulnerable-server.mjs)를 띄워 모든 템플릿이 잡는지 확인한다.
# 템플릿을 고친 뒤 오탐·미탐을 확인하는 회귀 테스트다.
set -euo pipefail

cd "$(dirname "$0")"

PORT=${SELFTEST_PORT:-3900}
ROOT=http://127.0.0.1:$PORT
OUT=reports/selftest.jsonl

if ! command -v nuclei >/dev/null; then
  nuclei() { docker run --rm --network host -v "$PWD:/work" -w /work "projectdiscovery/nuclei:${NUCLEI_TAG:-latest}" "$@"; }
fi

mkdir -p reports
PORT=$PORT node fixtures/vulnerable-server.mjs &
SERVER=$!
trap 'kill $SERVER' EXIT
curl -s --retry 20 --retry-connrefused --retry-delay 1 -o /dev/null "$ROOT/jwks"
kill -0 $SERVER 2>/dev/null || { echo "취약 서버를 띄우지 못함 (포트 $PORT 사용 중?)" >&2; exit 2; }

printf '%s\n' "$ROOT/mcp" "$ROOT/open" "$ROOT" > reports/selftest-targets.txt
nuclei -l reports/selftest-targets.txt -t templates \
  -var issuer="$ROOT" -var audience="$ROOT/mcp" \
  -jsonl -o "$OUT" -no-color -silent -duc >/dev/null

missing=0
for yaml in templates/*/*.yaml; do
  id=$(sed -n 's/^id: *//p' "$yaml")
  if grep -q "\"template-id\":\"$id\"" "$OUT"; then
    echo "ok      $id"
  else
    echo "MISSING $id"
    missing=1
  fi
done
exit $missing
