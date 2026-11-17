#!/usr/bin/env bash
# 인가 서버와 mcp-server(3000)를 백그라운드로 띄우고 응답할 때까지 기다린다. 로그는 *.log에 남는다.
# OTHER_MCP_URL이 있으면 aud 검증용 mcp-server를 3001에 하나 더 띄운다.
set -euo pipefail

pnpm -C auth start > auth.log 2>&1 &
./target/debug/mcp-server > mcp.log 2>&1 &
urls=(
  "$AUTH_ISSUER/.well-known/openid-configuration"
  http://localhost:3000/.well-known/oauth-protected-resource
)
if [[ -n "${OTHER_MCP_URL:-}" ]]; then
  PORT=3001 MCP_RESOURCE_URL=$OTHER_MCP_URL ./target/debug/mcp-server > other.log 2>&1 &
  urls+=(http://localhost:3001/.well-known/oauth-protected-resource)
fi

for url in "${urls[@]}"; do
  curl -sf --retry 30 --retry-connrefused --retry-delay 1 -o /dev/null "$url"
done
