# sample-mcp-rs

TS MCP 서버(sample-mcp)를 Rust로 옮긴 샘플. MCP 서버와 authorizer는 Rust, 인가 서버는 TS(oidc-provider)로 둔다.

| 경로 | 역할 |
|---|---|
| `crates/auth-common` | oidc-provider가 발급한 JWT 검증 (discovery → JWKS 캐시, iss/aud/exp 확인, `tenant_id` 클레임 필수) |
| `crates/mcp-server` | axum + rmcp Streamable HTTP(stateless). 로컬은 HTTP 서버, Lambda에서는 `lambda_http`로 실행 |
| `crates/authorizer` | API Gateway HTTP API용 Lambda authorizer (simple response) |
| `auth` | 샘플 인가 서버 (oidc-provider). 동적 클라이언트 등록, PKCE, resource indicator로 JWT 액세스 토큰 발급 |

## 환경 변수

| 이름 | 예 | 사용처 |
|---|---|---|
| `AUTH_ISSUER` | `http://localhost:4000` | 둘 다 |
| `MCP_RESOURCE_URL` | `http://localhost:3000/mcp` (토큰 `aud`) | 둘 다 |
| `MCP_ALLOWED_HOSTS` | `mcp.example.com` (쉼표 구분, 기본 localhost) | mcp-server |
| `PORT` | `3000` / `4000` | 각각 |

## 실행

```bash
pnpm -C auth install && pnpm -C auth start
AUTH_ISSUER=http://localhost:4000 MCP_RESOURCE_URL=http://localhost:3000/mcp cargo run -p mcp-server
pnpm dlx @modelcontextprotocol/inspector http://localhost:3000/mcp
```

Inspector의 로그인 화면에서 `alice`(tenant-a) 또는 `bob`(tenant-b)을 입력한다. 비밀번호는 검사하지 않는다.

## 샘플 한정 사항

- 로그인·동의 화면은 oidc-provider의 개발용 `devInteractions`다. 운영에서는 기존 제품 계정과 연동하는 화면으로 바꾼다.
- 서명 키와 저장소(클라이언트, 인가 코드)는 메모리에만 있어 재시작하면 사라진다.
- Windows에서는 MSVC 툴체인을 쓴다 (`rustup override set stable-x86_64-pc-windows-msvc`).
