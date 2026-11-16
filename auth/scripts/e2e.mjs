// 실행 중인 인가 서버와 MCP 서버로 전체 OAuth 흐름을 검증한다.
// 메타데이터 탐색 → 동적 등록 → PKCE 로그인·동의 → 토큰 교환 → MCP 도구 호출.
// oidc-provider가 실제로 발급한 토큰이 Rust 쪽 검증 규칙(typ, aud, scope, tenant_id 등)을 통과하는지 본다.
//
//   pnpm -C auth start                         # 인가 서버
//   cargo run -p mcp-server (환경 변수는 README) # MCP 서버
//   pnpm -C auth e2e
//
// OTHER_MCP_URL에 다른 MCP_RESOURCE_URL로 띄운 MCP 서버 주소를 주면,
// 이 resource로 발급된 토큰을 그 서버가 거부하는지도 확인한다.
// 두 서버는 같은 AUTH_ISSUER를 써야 한다. issuer가 다르면 aud가 아닌 다른 이유로도 401이 나서
// 이 검사가 aud 검증을 확인하지 못한다.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const MCP = process.env.MCP_RESOURCE_URL ?? 'http://localhost:3000/mcp';
const REDIRECT_URI = 'http://localhost:9999/cb';

async function discover() {
  const origin = new URL(MCP).origin;
  const path = new URL(MCP).pathname;
  const meta = await getJson(`${origin}/.well-known/oauth-protected-resource${path}`);
  return getJson(`${meta.authorization_servers[0]}/.well-known/openid-configuration`);
}

async function getJson(url, init) {
  const res = await fetch(url, init);
  assert.ok(res.ok, `${url} → ${res.status}`);
  return res.json();
}

/** devInteractions 화면을 따라가 인가 코드를 받는다. 로그인이 거부되면 응답 상태를 돌려준다. */
async function authorize(disc, clientId, login, scope = 'openid mcp:read') {
  const jar = new Map();
  const request = async (url, init = {}) => {
    const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(url, { redirect: 'manual', ...init, headers: { cookie, ...init.headers } });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return res;
  };

  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  let url = `${disc.authorization_endpoint}?${new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: MCP,
    state: 'e2e',
  })}`;

  let res = await request(url);
  for (let step = 0; step < 12; step++) {
    if (res.status >= 300 && res.status < 400) {
      url = new URL(res.headers.get('location'), url).toString();
      if (url.startsWith(REDIRECT_URI)) {
        return { code: new URL(url).searchParams.get('code'), verifier };
      }
      res = await request(url);
      continue;
    }
    const html = await res.text();
    const action = html.match(/action="([^"]+)"/)?.[1];
    if (!action) return { rejected: res.status };
    const form = html.includes('value="login"')
      ? { prompt: 'login', login, password: 'x' }
      : { prompt: 'consent' };
    url = new URL(action, url).toString();
    res = await request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form),
    });
  }
  throw new Error('authorization did not finish');
}

function callTool(token, name, args = {}) {
  return fetch(MCP, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-11-25',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
  });
}

async function toolResult(token, name, args) {
  const res = await callTool(token, name, args);
  assert.equal(res.status, 200, `tools/call ${name}`);
  return (await res.json()).result;
}

/** 로그인부터 토큰 교환까지 거쳐 액세스 토큰을 받는다. */
async function accessToken(disc, clientId, login, scope) {
  const { code, verifier } = await authorize(disc, clientId, login, scope);
  assert.ok(code, `${login}: no authorization code`);
  const token = await getJson(disc.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
      resource: MCP,
    }),
  });
  return token.access_token;
}

const disc = await discover();
const client = await getJson(disc.registration_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    redirect_uris: [REDIRECT_URI],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code'],
  }),
});

let lastToken;
for (const [login, tenant] of [['alice', 'tenant-a'], ['bob', 'tenant-b']]) {
  const token = await accessToken(disc, client.client_id, login);
  const whoami = (await toolResult(token, 'whoami')).structuredContent;
  assert.deepEqual(whoami, { sub: login, tenant_id: tenant, scopes: ['mcp:read'] });
  const echo = await toolResult(token, 'echo', { message: 'hi' });
  assert.equal(echo.content[0].text, `[${tenant}] hi`);
  console.log(`ok  ${login} → ${tenant} (whoami, echo)`);
  lastToken = token;
}

// mcp:read 없이 받은 토큰은 403 insufficient_scope로 스코프를 올리라고 알린다.
{
  const token = await accessToken(disc, client.client_id, 'alice', 'openid');
  const res = await callTool(token, 'whoami');
  assert.equal(res.status, 403, 'token without mcp:read must be rejected');
  assert.match(res.headers.get('www-authenticate') ?? '', /insufficient_scope/);
  console.log('ok  token without mcp:read rejected (403 insufficient_scope)');
}

// 선택: 다른 resource로 띄운 MCP 서버가 이 토큰(aud가 다름)을 거부하는지 본다.
if (process.env.OTHER_MCP_URL) {
  const res = await fetch(process.env.OTHER_MCP_URL, {
    method: 'POST',
    headers: { authorization: `Bearer ${lastToken}`, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(res.status, 401, 'token for another resource must be rejected');
  assert.match(res.headers.get('www-authenticate') ?? '', /invalid_token/);
  console.log('ok  token rejected by another resource (401 invalid_token)');
}

const unknown = await authorize(disc, client.client_id, 'mallory');
assert.equal(unknown.rejected, 403, 'unknown account must be rejected at login');
console.log('ok  mallory rejected (403)');
