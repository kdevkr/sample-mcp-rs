// 템플릿이 실제로 잡는지 확인하는 일부러 취약한 서버. 로컬 검사 전용이다.
// MCP(:3900/mcp, :3900/open)와 인가 서버 역할을 한 프로세스에서 흉내 낸다.
// TLS_CERT, TLS_KEY를 주면 같은 응답을 https(:TLS_PORT, 기본 3943)로도 연다(tlsx 확인용).
//   node security/fixtures/vulnerable-server.mjs
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';

const PORT = Number(process.env.PORT ?? 3900);
const TLS_PORT = Number(process.env.TLS_PORT ?? 3943);
const ROOT = `http://localhost:${PORT}`;

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

const readBody = (req) =>
  new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => resolve(body));
  });

const initialize = (id) => ({
  jsonrpc: '2.0',
  id,
  result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'vulnerable', version: '0' } },
});

async function handle(req, res) {
  const cors = { 'access-control-allow-origin': '*' };
  const url = new URL(req.url, ROOT);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, { ...cors, 'access-control-allow-methods': 'POST' });
    return res.end();
  }
  if (url.pathname === '/.well-known/openid-configuration') {
    return json(res, 200, {
      issuer: ROOT,
      jwks_uri: `${ROOT}/jwks`,
      registration_endpoint: `${ROOT}/reg`,
      code_challenge_methods_supported: ['plain', 'S256'],
      grant_types_supported: ['implicit', 'authorization_code'],
    });
  }
  if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
    return json(res, 200, { resource: `${ROOT}/mcp`, authorization_servers: [ROOT] });
  }
  if (url.pathname === '/jwks') {
    // 개인 키(d)를 그대로 노출한다.
    return json(res, 200, { keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA', d: 'AA' }] });
  }
  if (url.pathname === '/reg' && req.method === 'POST') {
    // 등록 요청의 jwks_uri를 검사 없이 서버에서 가져온다(SSRF).
    const client = JSON.parse((await readBody(req)) || '{}');
    if (client.jwks_uri) await fetch(client.jwks_uri, { signal: AbortSignal.timeout(5000) }).catch(() => {});
    return json(res, 201, { client_id: 'vulnerable', ...client });
  }
  // /mcp: Bearer 토큰이 있기만 하면 서명을 보지 않고 통과. 401에 resource_metadata가 없다.
  // /open: 토큰 없이도 통과.
  if ((url.pathname === '/mcp' || url.pathname === '/open') && req.method === 'POST') {
    if (url.pathname === '/mcp' && !req.headers.authorization?.startsWith('Bearer ')) {
      res.writeHead(401, { ...cors, 'www-authenticate': 'Bearer' });
      return res.end();
    }
    let id = 1;
    try {
      id = JSON.parse(await readBody(req)).id ?? 1;
    } catch {}
    return json(res, 200, initialize(id), cors);
  }
  json(res, 404, { error: 'not found' });
}

createServer(handle).listen(PORT, '127.0.0.1', () => console.log(`vulnerable server on ${ROOT}`));

if (process.env.TLS_CERT && process.env.TLS_KEY) {
  // 자체 서명 인증서. tlsx가 self_signed로 잡아야 한다.
  createTlsServer({ cert: readFileSync(process.env.TLS_CERT), key: readFileSync(process.env.TLS_KEY) }, handle).listen(
    TLS_PORT,
    '127.0.0.1',
    () => console.log(`vulnerable tls server on https://127.0.0.1:${TLS_PORT}`),
  );
}
