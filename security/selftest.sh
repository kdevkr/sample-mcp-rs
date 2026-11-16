#!/usr/bin/env bash
# 일부러 취약한 서버(fixtures/vulnerable-server.mjs)를 띄워 모든 검사가 잡는지 확인한다.
# 템플릿·검사를 고친 뒤 미탐을 확인하는 회귀 테스트다.
# oauth-dcr-ssrf는 interactsh(외부 OOB 서버)를 쓰므로 인터넷이 필요하다. OAST=0이면 건너뛴다.
set -euo pipefail

cd "$(dirname "$0")"

PORT=${SELFTEST_PORT:-3900}
TLS_PORT=${SELFTEST_TLS_PORT:-3943}
ROOT=http://127.0.0.1:$PORT
OAST=${OAST:-1}
OUT=reports/selftest

pd() { docker run --rm --network host -v "$PWD:/work" -w /work "projectdiscovery/$1:$2" "${@:3}"; }
command -v nuclei >/dev/null || nuclei() { pd nuclei "${NUCLEI_TAG:-latest}" "$@"; }
command -v tlsx >/dev/null || tlsx() { pd tlsx "${TLSX_TAG:-latest}" "$@"; }
command -v naabu >/dev/null || naabu() { pd naabu "${NAABU_TAG:-latest}" "$@"; }

rm -rf "$OUT"
mkdir -p "$OUT"
# tlsx가 잡을 자체 서명 인증서
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=vulnerable.local" -keyout "$OUT/tls.key" -out "$OUT/tls.crt" 2>/dev/null

PORT=$PORT TLS_PORT=$TLS_PORT TLS_CERT=$OUT/tls.crt TLS_KEY=$OUT/tls.key node fixtures/vulnerable-server.mjs &
SERVER=$!
trap 'kill $SERVER' EXIT
curl -s --retry 20 --retry-connrefused --retry-delay 1 -o /dev/null "$ROOT/jwks"
curl -sk --retry 20 --retry-connrefused --retry-delay 1 -o /dev/null "https://127.0.0.1:$TLS_PORT/jwks"
kill -0 $SERVER 2>/dev/null || { echo "취약 서버를 띄우지 못함 (포트 $PORT, $TLS_PORT 사용 중?)" >&2; exit 2; }

oast_flag=()
[ "$OAST" = 1 ] || oast_flag=(-ni)
printf '%s\n' "$ROOT/mcp" "$ROOT/open" "$ROOT" > "$OUT/targets.txt"
nuclei -l "$OUT/targets.txt" -t templates "${oast_flag[@]}" \
  -var issuer="$ROOT" -var audience="$ROOT/mcp" \
  -jsonl -o "$OUT/nuclei-custom.jsonl" -no-color -silent -duc >/dev/null
tlsx -u "127.0.0.1:$TLS_PORT" -tls-version -cipher -expired -self-signed -mismatched \
  -json -o "$OUT/tlsx.jsonl" -silent -no-color >/dev/null
naabu -host 127.0.0.1 -p "$PORT,$TLS_PORT" -s c -json -o "$OUT/naabu.jsonl" -silent -no-color >/dev/null

# 허용 포트를 비워 두 포트 모두 unexpected-open-port로 나오게 한다.
summary=$(ALLOWED_PORTS= node summary.mjs "$OUT" || true)

expected=$(sed -n 's/^id: *//p' templates/*/*.yaml)
[ "$OAST" = 1 ] || expected=$(grep -v '^oauth-dcr-ssrf$' <<<"$expected")
expected+=$'\ntls-self-signed-cert\ntls-hostname-mismatch\nunexpected-open-port'

missing=0
while read -r id; do
  if grep -q " $id " <<<"$summary"; then
    echo "ok      $id"
  else
    echo "MISSING $id"
    missing=1
  fi
done <<<"$expected"
exit $missing
