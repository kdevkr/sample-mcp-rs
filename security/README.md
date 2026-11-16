# 취약점 검사 (ProjectDiscovery)

[ProjectDiscovery](https://docs.projectdiscovery.io/home) 도구로 로컬 MCP 서버와 인가 서버를 검사하는 샘플이다.
허락받은 대상에만 실행한다.

| 도구 | 용도 |
|---|---|
| `httpx` | 대상 응답·기술 스택 확인 |
| `nuclei` | 커스텀 템플릿으로 인증·설정 취약점 검사 |
| interactsh | nuclei에 내장된 OOB 서버. SSRF처럼 서버가 밖으로 요청하는지 확인 |
| `tlsx` | TLS 버전, 인증서 만료·자체 서명·호스트 불일치 |
| `naabu` | 허용 목록 밖에 열린 포트 |

## 구성

| 경로 | 내용 |
|---|---|
| `scan.sh` | httpx → 템플릿 문법 검사 → nuclei → tlsx → naabu → 요약 |
| `summary.mjs` | 도구별 결과를 모아 심각도 순으로 출력. high 이상이면 종료 코드 1 |
| `selftest.sh` | 취약한 서버에서 모든 검사가 잡히는지 확인 |
| `fixtures/vulnerable-server.mjs` | 일부러 취약하게 만든 서버 (selftest용) |
| `templates/mcp` | MCP 엔드포인트 템플릿 |
| `templates/oauth` | 인가 서버·메타데이터 템플릿 |
| `reports/` | 결과 (git에 넣지 않음) |

### nuclei 템플릿

| ID | 심각도 | 확인 내용 |
|---|---|---|
| `mcp-unauthenticated-access` | high | 토큰 없이 `initialize` 성공 |
| `mcp-forged-jwt-accepted` | critical | `alg=none`, 약한 HS256 키로 만든 토큰을 받음 |
| `mcp-missing-resource-metadata` | low | 401의 `WWW-Authenticate`에 `resource_metadata` 없음 |
| `mcp-cors-any-origin` | low | 임의 Origin 허용, Origin 검사 없음 |
| `oauth-protected-resource-metadata` | info | RFC 9728 메타데이터에서 인가 서버 주소 추출 |
| `oidc-weak-config` | medium | PKCE `plain`, implicit grant, PKCE 미지원 |
| `jwks-private-key-exposure` | critical | 공개 JWKS에 개인 키·대칭 키 포함 |
| `oauth-dcr-ssrf` | high | 동적 클라이언트 등록의 `jwks_uri`·`logo_uri`·`policy_uri`를 서버가 가져감 (interactsh) |

### tlsx·naabu 판정

| ID | 심각도 | 조건 |
|---|---|---|
| `tls-expired-cert` | high | 인증서 만료 |
| `tls-self-signed-cert` | medium | 자체 서명 인증서 |
| `tls-hostname-mismatch` | medium | 인증서 이름과 호스트 불일치 |
| `tls-deprecated-*` | medium | SSL 3.0, TLS 1.0, TLS 1.1 |
| `unexpected-open-port` | low | `ALLOWED_PORTS`에 없는 열린 포트 |

## 설치

Go가 있으면 공식 문서대로 설치한다. `$(go env GOPATH)/bin`이 PATH에 있어야 한다.

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

```bash
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
```

```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

- 커뮤니티 템플릿은 nuclei 첫 실행 때 `~/nuclei-templates`로 받는다.
- 바이너리가 없으면 공식 Docker 이미지로 실행한다(Linux 전용, `--network host`). 태그는 `NUCLEI_TAG`, `HTTPX_TAG`, `TLSX_TAG`, `NAABU_TAG`로 고정한다.

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
| `OAST` | `1` | `0`이면 interactsh를 쓰지 않는다(`oauth-dcr-ssrf` 결과 없음) |
| `COMMUNITY` | `0` | `1`이면 커뮤니티 템플릿(`misconfig,exposure,token`)도 실행 |
| `TLS_TARGETS` | 비어 있음 | tlsx 대상 `host:port` (쉼표 구분). 비어 있으면 건너뜀 |
| `PORT_HOST` | 비어 있음 | naabu 대상 호스트. 비어 있으면 건너뜀 |
| `PORT_RANGE` | `1-10000` | naabu 포트 범위 |
| `ALLOWED_PORTS` | `3000,4000` | 열려 있어도 되는 포트 |

- 대상 주소는 `127.0.0.1`로 쓴다. Windows의 nuclei는 `localhost`를 찾지 못한다(`no address found for host`).
- `ISSUER`, `AUDIENCE`가 서버 설정과 다르면 위조 토큰이 서명 검사 전에 거부돼 검사 의미가 없다.
- interactsh는 ProjectDiscovery의 공개 OOB 서버(`oast.*`)를 쓴다. 검사 대상이 그 주소로 요청하므로 외부 통신이 막힌 환경이나 공개되면 안 되는 대상이면 `OAST=0`으로 끈다.
  DNS 조회만 와도 서버가 URL을 처리한 것으로 보고 잡는다.
- 개발 PC에서 `PORT_HOST=127.0.0.1`로 돌리면 다른 개발 서버 포트도 `unexpected-open-port`로 나온다. `PORT_RANGE`를 좁혀서 쓴다.
- 결과: `reports/scan/` 아래 `httpx.txt`, `nuclei-*.jsonl`, `tlsx.jsonl`, `naabu.jsonl`, `markdown/`

배포한 https 서버를 검사할 때:

```bash
MCP_URL=https://mcp.example.com/mcp AUTH_URL=https://auth.example.com TLS_TARGETS=mcp.example.com:443,auth.example.com:443 security/scan.sh
```

템플릿 하나만 돌릴 때:

```bash
nuclei -u http://127.0.0.1:3000/mcp -t security/templates/mcp/mcp-forged-jwt-accepted.yaml -debug
```

## 회귀 테스트

```bash
security/selftest.sh
```

취약한 서버(:3900, https :3943)를 띄우고 nuclei 템플릿, tlsx, naabu 판정이 모두 잡히는지 확인한다. 하나라도 못 잡으면 종료 코드 1이다.
`oauth-dcr-ssrf`는 인터넷이 필요하다. 오프라인이면 `OAST=0`으로 건너뛴다.

## 이 샘플에서 나오는 결과

기본 설정으로 띄우면 아래가 나온다. 둘 다 샘플이라 그대로 둔 설정이다.

| 템플릿 | 이유 | 운영에서 할 일 |
|---|---|---|
| `mcp-cors-any-origin` | `MCP_ALLOWED_ORIGINS`가 비어 있으면 모든 Origin 허용 | `MCP_ALLOWED_ORIGINS` 설정 |
| `oidc-weak-config` | oidc-provider가 implicit grant를 광고 | 운영 인가 서버에서 implicit 끄기 |

`oauth-dcr-ssrf`는 나오지 않는다. oidc-provider는 등록할 때 `jwks_uri` 등을 가져가지 않는다.

## 새 템플릿 추가

1. `templates/` 아래에 YAML을 만든다. 문법은 [템플릿 문서](https://docs.projectdiscovery.io/templates/introduction)를 따른다.
2. `nuclei -validate -t security/templates`로 확인한다.
3. `fixtures/vulnerable-server.mjs`에 그 취약점을 넣고 `selftest.sh`로 잡히는지 확인한다.
4. `scan.sh`로 실제 서버에서 오탐이 없는지 확인한다.
