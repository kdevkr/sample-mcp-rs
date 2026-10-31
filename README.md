# sample-mcp-rs

TS MCP 서버(sample-mcp)의 리소스 서버 부분을 Rust로 옮긴 워크스페이스. 인가 서버(oidc-provider)는 TS 그대로 둔다.

| crate | 역할 |
|---|---|
| `auth-common` | oidc-provider가 발급한 JWT 검증 (discovery → JWKS 캐시, iss/aud/exp 확인, `tenant_id` 클레임 필수) |
| `mcp-server` | axum + rmcp Streamable HTTP(stateless). 로컬은 HTTP 서버, Lambda에서는 `lambda_http`로 실행 |
| `authorizer` | API Gateway HTTP API용 Lambda authorizer (simple response) |

## 환경 변수

| 이름 | 예 |
|---|---|
| `AUTH_ISSUER` | `http://localhost:4000` (TS 인가 서버 issuer) |
| `MCP_RESOURCE_URL` | `http://localhost:3000/mcp` (토큰 `aud`와 일치해야 함) |
| `MCP_ALLOWED_HOSTS` | `mcp.example.com` (쉼표 구분, 기본 localhost) |
| `PORT` | `3000` |

## 실행

```bash
AUTH_ISSUER=http://localhost:4000 MCP_RESOURCE_URL=http://localhost:3000/mcp cargo run -p mcp-server
pnpm dlx @modelcontextprotocol/inspector http://localhost:3000/mcp
```

Windows에서는 MSVC 툴체인을 쓴다 (`rustup override set stable-x86_64-pc-windows-msvc`).
