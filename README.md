# sample-mcp-rs

TypeScript로 만든 MCP 서버를 Rust로 다시 구성한 샘플이다.

- MCP 서버, 토큰 검증: Rust
- 인가 서버: TypeScript (oidc-provider)

## 구성

```
MCP 클라이언트 ──(Bearer JWT)──▶ mcp-server (Rust, :3000)
      │                              │
      │                              │ JWKS 조회·캐시
      │                              ▼
      └──(로그인, 토큰 발급)──▶ auth (TS oidc-provider, :4000)
```

| 경로 | 언어 | 역할 |
|---|---|---|
| `crates/mcp-server` | Rust | MCP 서버 |
| `crates/auth-common` | Rust | JWT 검증 공용 모듈 |
| `crates/authorizer` | Rust | API Gateway Lambda authorizer |
| `auth` | TypeScript | 샘플 인가 서버 |

### mcp-server

- axum + rmcp Streamable HTTP (stateless)
- 로컬에서는 HTTP 서버로 실행한다.
- Lambda에서는 `lambda_http`로 실행한다.

### auth-common

- JWKS를 받아 캐시한다.
- `iss`, `aud`, `exp`를 검증한다.
- `tenant_id` 클레임이 없으면 거부한다.

### auth

- 동적 클라이언트 등록
- PKCE 필수
- ES256 JWT 액세스 토큰 발급

## 빠른 시작

필요 도구: Rust(stable), Node 24, pnpm

**1. 인가 서버**

```bash
pnpm -C auth install
pnpm -C auth start
```

**2. MCP 서버**

```bash
AUTH_ISSUER=http://localhost:4000 \
MCP_RESOURCE_URL=http://localhost:3000/mcp \
cargo run -p mcp-server
```

**3. MCP Inspector로 접속**

```bash
pnpm dlx @modelcontextprotocol/inspector http://localhost:3000/mcp
```

Inspector가 로그인 화면을 띄우면 아래 계정 중 하나를 입력한다.
비밀번호는 검사하지 않는다.

| 계정 | 테넌트 |
|---|---|
| `alice` | `tenant-a` |
| `bob` | `tenant-b` |

### 제공 도구

| 도구 | 설명 |
|---|---|
| `whoami` | 토큰의 사용자, 테넌트, 스코프 반환 |
| `echo` | 입력 문자열을 테넌트 ID와 함께 반환 |

## 테스트

```bash
cargo test --workspace
```

단위 테스트와 라우터 테스트다. 테스트 안에서 키를 만들어 서명한 토큰으로 검증 규칙을 확인한다.

```bash
pnpm -C auth e2e
```

인가 서버와 MCP 서버를 띄운 상태에서 실행한다.
oidc-provider가 실제로 발급한 토큰으로 로그인부터 도구 호출까지 확인한다.

`OTHER_MCP_URL`을 주면 `aud` 검증도 실제 토큰으로 확인한다.
다른 `MCP_RESOURCE_URL`로 MCP 서버를 하나 더 띄우고 그 주소를 넣는다.

```bash
OTHER_MCP_URL=http://localhost:3001/other pnpm -C auth e2e
```

두 MCP 서버는 같은 `AUTH_ISSUER`를 써야 한다. 그래야 401이 `aud` 불일치 때문에 난다는 게 확인된다.

GitHub Actions(`.github/workflows/ci.yml`)는 푸시와 PR마다 아래를 실행한다.

- `cargo fmt --check`, `clippy -D warnings`, `cargo test`
- `cargo audit`, `pnpm audit`
- 인가 서버 `typecheck`
- 위 서버 세 개를 띄운 e2e (`OTHER_MCP_URL` 포함)

## 환경 변수

| 이름 | 사용처 | 기본값 |
|---|---|---|
| `AUTH_ISSUER` | 공통 | `http://localhost:4000` (auth만) |
| `MCP_RESOURCE_URL` | 공통 | `http://localhost:3000/mcp` (auth만) |
| `AUTH_JWKS_URI` | Rust | 비어 있음 (discovery에서 찾음) |
| `MCP_ALLOWED_HOSTS` | mcp-server | `MCP_RESOURCE_URL` 호스트 + 루프백 |
| `MCP_ALLOWED_ORIGINS` | mcp-server | 비어 있음 (모든 Origin 허용) |
| `HOST` | mcp-server (로컬 실행) | `127.0.0.1` |
| `PORT` | 각각 | `3000` / `4000` |
| `RUST_LOG` | Rust | `info` |

- `AUTH_ISSUER`, `MCP_RESOURCE_URL`은 Rust 쪽에서 필수다.
- `AUTH_ISSUER`, `MCP_RESOURCE_URL`, `AUTH_JWKS_URI`는 https만 받는다.
  `localhost`, `127.0.0.1`, `[::1]`일 때만 http를 허용한다(로컬 개발용).
- `AUTH_ISSUER`는 인가 서버의 issuer와 끝의 `/`까지 정확히 같아야 한다.
  다르면 모든 요청이 503이 되고, 로그에 `issuer mismatch`가 남는다.
- 서명 키(JWKS) 주소는 discovery 문서에서 찾는다.
  이 주소가 https가 아니거나 issuer와 호스트가 다르면 받지 않는다(503, 로그에 `untrusted jwks_uri`).
  키를 다른 호스트에서 제공하는 인가 서버라면 `AUTH_JWKS_URI`로 직접 지정한다. 이때는 discovery를 쓰지 않는다.
- `HOST`는 컨테이너에서 띄울 때 `0.0.0.0`으로 바꾼다.
- `MCP_ALLOWED_ORIGINS`는 허용할 브라우저 Origin 목록이다(쉼표 구분, 예: `https://app.example.com`).
  `scheme://host[:port]` 형태만 받고, 경로·쿼리가 붙은 값은 시작할 때 거부한다. 대소문자와 기본 포트(`:443`, `:80`)는 무시한다.
  설정하면 목록에 없는 Origin의 요청은 403으로 거부한다(Origin 헤더가 없는 요청은 통과).
  운영에서는 반드시 설정한다.
- `MCP_RESOURCE_URL`은 토큰의 `aud`로 쓰인다.
  경로가 그대로 MCP 엔드포인트가 된다(예: `/mcp`, `/prod/mcp`).
  스킴이나 경로가 없거나 경로에 영숫자와 `-._~` 외 문자가 있으면 시작하지 않는다.
- `MCP_ALLOWED_HOSTS`는 쉼표로 구분한다. DNS 리바인딩을 막는 Host 허용 목록이다.

## 인증 흐름

1. 토큰 없이 `/mcp`를 호출하면 401을 받는다.
   응답 헤더 `WWW-Authenticate`에 메타데이터 주소가 들어 있다.
2. 클라이언트는 `/.well-known/oauth-protected-resource`에서 인가 서버 주소를 찾는다.
3. 인가 서버에 동적 등록(`/reg`)한다.
4. PKCE로 로그인하고, `resource`를 MCP 서버 URL로 지정해 토큰을 받는다.
5. 액세스 토큰으로 `/mcp`를 호출한다.
   토큰에는 `aud`(MCP 서버)와 `tenant_id`가 들어 있다.
6. 도구는 검증된 `tenant_id`만 신뢰한다.

### 토큰 검증 규칙

| 상황 | 응답 |
|---|---|
| 토큰 없음 | 401 + `resource_metadata` |
| 서명·`iss`·`aud`·`exp`·`nbf` 오류, `typ`이 `at+jwt`가 아님, `sub`·`tenant_id`가 없거나 빈 값 | 401 `invalid_token` |
| 토큰의 `alg`가 서명 키(JWK)의 종류·`alg`와 맞지 않음 | 401 `invalid_token` |
| `mcp:read` 스코프 없음 | 403 `insufficient_scope` |
| 인가 서버에서 서명 키를 받지 못함 | 503 |

- 서명 키(JWKS)는 캐시하고 10분마다 다시 받는다. 인가 서버에서 빠진 키는 그때부터 거부된다.
- 인가 서버 장애 중에는 이미 받아 둔 키로 계속 검증한다.
  단, 마지막으로 키를 받은 뒤 1시간이 지나면 더 쓰지 않고 503을 돌려준다.
  이 대체 동작은 키를 이미 받아 둔(웜) 인스턴스에만 효과가 있다.
  장애 중 새로 뜬 Lambda 인스턴스는 키가 없어 바로 503을 돌려준다.
- 2048비트 미만 RSA 키(앞에 채운 0은 길이에 넣지 않음), 해석할 수 없는 키, 쓸 수 있는 알고리즘이 없는 키는 받지 않고 경고 로그를 남긴다.
  JWKS에 같은 kid가 여러 번 나오면 처음 키만 쓰고 경고 로그를 남긴다.
- JWKS를 받을 때 리다이렉트는 따라가지 않는다(3xx는 503, 로그에 `redirects are not followed`).
  discovery·JWKS 응답은 64KB까지만 읽는다.
- 이 검증은 인가 서버를 신뢰한다는 전제다. 인가 서버는 어떤 사용자·테넌트의 토큰이든 발급할 수 있으므로,
  issuer는 하나로 고정하고 https로만 키를 받는다.
- 모르는 키 ID나 조회 실패가 있어도 재조회는 10초에 한 번만 한다.
- 브라우저의 CORS preflight(`OPTIONS`)는 인증 없이 통과한다.
  `MCP_ALLOWED_ORIGINS`가 없으면 모든 Origin을 허용한다(쿠키 없이 Bearer 토큰만 쓰므로 샘플에서는 괜찮다).

## 배포 메모

**Lambda**

- `AWS_LAMBDA_RUNTIME_API`를 감지해 `lambda_http`로 실행한다.
- 인스턴스 간 세션을 공유할 수 없어 stateless로 고정했다.
- Lambda가 받는 요청 경로와 `MCP_RESOURCE_URL` 경로가 같아야 한다.
  API Gateway 스테이지 이름이 경로에 붙는 구성이면 그 경로까지 `MCP_RESOURCE_URL`에 넣는다.
- CORS는 mcp-server가 처리한다. API Gateway에서도 CORS를 켜면 `Access-Control-*` 헤더가 겹치므로 한쪽만 켠다.

**authorizer**

- `/mcp`와 `/.well-known/*`에는 붙이지 않는다.
- 거부하면 API Gateway가 `WWW-Authenticate` 없이 403을 돌려준다.
- 그러면 MCP 클라이언트가 로그인 흐름을 시작하지 못한다.
- MCP 라우트는 mcp-server가 직접 검증한다.

## 샘플 한정 사항

- 로그인 화면은 oidc-provider의 개발용 `devInteractions`다.
  운영에서는 기존 제품 계정과 연동하는 화면으로 바꾼다.
- 인가 서버는 `NODE_ENV=production`이면 시작하지 않는다.
- 서명 키, 클라이언트, 인가 코드는 메모리에만 있다.
  재시작하면 사라지므로 다시 로그인한다.
- Windows에서는 MSVC 툴체인을 쓴다.

```bash
rustup override set stable-x86_64-pc-windows-msvc
```
