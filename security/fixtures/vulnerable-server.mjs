// 템플릿이 실제로 잡는지 확인하는 일부러 취약한 서버. 로컬 검사 전용이다.
// MCP(:3900/mcp, :3900/open)와 인가 서버 역할을 한 프로세스에서 흉내 낸다.
//   node security/fixtures/vulnerable-server.mjs
import { createServer } from 'node:http';

const PORT = Number(process.env.PORT ?? 3900);
const ROOT = `http://localhost:${PORT}`;

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

const initialize = (id) => ({
  jsonrpc: '2.0',
  id,
  result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'vulnerable', version: '0' } },
});

createServer((req, res) => {
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
  // /mcp: Bearer 토큰이 있기만 하면 서명을 보지 않고 통과. 401에 resource_metadata가 없다.
  // /open: 토큰 없이도 통과.
  if ((url.pathname === '/mcp' || url.pathname === '/open') && req.method === 'POST') {
    if (url.pathname === '/mcp' && !req.headers.authorization?.startsWith('Bearer ')) {
      res.writeHead(401, { ...cors, 'www-authenticate': 'Bearer' });
      return res.end();
    }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      let id = 1;
      try {
        id = JSON.parse(body).id ?? 1;
      } catch {}
      json(res, 200, initialize(id), cors);
    });
    return;
  }
  json(res, 404, { error: 'not found' });
}).listen(PORT, '127.0.0.1', () => console.log(`vulnerable server on ${ROOT}`));
