# 취약점 검사 (ProjectDiscovery)

[ProjectDiscovery](https://docs.projectdiscovery.io/home)의 `httpx`, `nuclei`로 로컬 MCP 서버와 인가 서버를 검사하는 샘플이다.
허락받은 대상에만 실행한다.

## 구성

| 경로 | 내용 |
|---|---|
| `scan.sh` | httpx 확인 → 템플릿 문법 검사 → nuclei 검사 → 요약 |
| `selftest.sh` | 취약한 서버에서 모든 템플릿이 잡히는지 확인 |
| `fixtures/vulnerable-server.mjs` | 일부러 취약하게 만든 서버 (selftest용) |
| `templates/mcp` | MCP 엔드포인트 템플릿 |
| `templates/oauth` | 인가 서버·메타데이터 템플릿 |
| `reports/` | 결과 (git에 넣지 않음) |

### 템플릿

| ID | 심각도 | 확인 내용 |
|---|---|---|
| `mcp-unauthenticated-access` | high | 토큰 없이 `initialize` 성공 |
| `mcp-forged-jwt-accepted` | critical | `alg=none`, 약한 HS256 키로 만든 토큰을 받음 |
| `mcp-missing-resource-metadata` | low | 401의 `WWW-Authenticate`에 `resource_metadata` 없음 |
| `mcp-cors-any-origin` | low | 임의 Origin 허용, Origin 검사 없음 |
| `oauth-protected-resource-metadata` | info | RFC 9728 메타데이터에서 인가 서버 주소 추출 |
| `oidc-weak-config` | medium | PKCE `plain`, implicit grant, PKCE 미지원 |
| `jwks-private-key-exposure` | critical | 공개 JWKS에 개인 키·대칭 키 포함 |

## 설치

Go가 있으면 공식 문서대로 설치한다.

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

`$(go env GOPATH)/bin`이 PATH에 있어야 한다.
커뮤니티 템플릿은 nuclei 첫 실행 때 `~/nuclei-templates`로 받는다.

## 실행

루트 README의 빠른 시작대로 인가 서버(:4000)와 MCP 서버(:3000)를 띄운 뒤 실행한다.

```bash
security/scan.sh
```

| 변수 | 기본값 | 설명 |
|---|---|---|
| `MCP_URL` | `http://127.0.0.1:3000/mcp` | 검사할 MCP 엔드포인트 |
| `AUTH_URL` | `http://127.0.0.1:4000` | 검사할 인가 서버 |
| `ISSUER` | `http://localhost:4000` | 위조 토큰의 `iss`. 서버의 `AUTH_ISSUER`와 같게 |
| `AUDIENCE` | `http://localhost:3000/mcp` | 위조 토큰의 `aud`. 서버의 `MCP_RESOURCE_URL`과 같게 |
| `COMMUNITY` | `0` | `1`이면 커뮤니티 템플릿(`misconfig,exposure,token`)도 실행 |

- 대상 주소는 `127.0.0.1`로 쓴다. Windows의 nuclei는 `localhost`를 찾지 못한다(`no address found for host`).
- `ISSUER`, `AUDIENCE`가 서버 설정과 다르면 위조 토큰이 서명 검사 전에 거부돼 검사 의미가 없다.
- `httpx`, `nuclei`가 없으면 Docker 이미지로 실행한다(Linux 전용). 태그는 `NUCLEI_TAG`, `HTTPX_TAG`로 고정한다.
- high 이상이 있으면 종료 코드 1이다. CI에서 그대로 실패 조건으로 쓴다.
- 결과: `reports/httpx.txt`, `reports/nuclei-*.jsonl`, `reports/markdown/`

템플릿 하나만 돌릴 때:

```bash
nuclei -u http://127.0.0.1:3000/mcp -t security/templates/mcp/mcp-forged-jwt-accepted.yaml -debug
```

## 템플릿 회귀 테스트

```bash
security/selftest.sh
```

:3900에 취약한 서버를 띄우고 모든 템플릿이 잡는지 확인한다. 하나라도 못 잡으면 종료 코드 1이다.

## 이 샘플에서 나오는 결과

기본 설정으로 띄우면 아래가 나온다. 둘 다 샘플이라 그대로 둔 설정이다.

| 템플릿 | 이유 | 운영에서 할 일 |
|---|---|---|
| `mcp-cors-any-origin` | `MCP_ALLOWED_ORIGINS`가 비어 있으면 모든 Origin 허용 | `MCP_ALLOWED_ORIGINS` 설정 |
| `oidc-weak-config` | oidc-provider가 implicit grant를 광고 | 운영 인가 서버에서 implicit 끄기 |

## 새 템플릿 추가

1. `templates/` 아래에 YAML을 만든다. 문법은 [템플릿 문서](https://docs.projectdiscovery.io/templates/introduction)를 따른다.
2. `nuclei -validate -t security/templates`로 확인한다.
3. `fixtures/vulnerable-server.mjs`에 그 취약점을 넣고 `selftest.sh`로 잡히는지 확인한다.
4. `scan.sh`로 실제 서버에서 오탐이 없는지 확인한다.
