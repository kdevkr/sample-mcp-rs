// 샘플용 OIDC 인가 서버. MCP 서버(Rust)가 검증할 JWT 액세스 토큰을 발급한다.
// 로그인은 oidc-provider의 devInteractions(개발용 화면)를 그대로 쓴다. 운영 금지.

import { generateKeyPairSync } from 'node:crypto';
import Provider, { type Configuration, errors, type KoaContextWithOIDC } from 'oidc-provider';

// devInteractions는 비밀번호를 검사하지 않는다. 운영에 잘못 배포되지 않게 막는다.
if (process.env.NODE_ENV === 'production') {
  throw new Error('sample auth server must not run in production');
}

const ISSUER = process.env.AUTH_ISSUER ?? 'http://localhost:4000';
const MCP_RESOURCE_URL = process.env.MCP_RESOURCE_URL ?? 'http://localhost:3000/mcp';
const PORT = Number(process.env.PORT ?? 4000);

// 샘플 계정과 소속 테넌트. 실제로는 기존 제품의 계정 저장소를 조회한다.
const ACCOUNTS: Record<string, { tenantId: string }> = {
  alice: { tenantId: 'tenant-a' },
  bob: { tenantId: 'tenant-b' },
};

// 'toString' 같은 프로토타입 키가 계정으로 잡히지 않게 자기 속성만 본다.
function findSampleAccount(id: string) {
  return Object.hasOwn(ACCOUNTS, id) ? ACCOUNTS[id] : undefined;
}

// 재시작마다 새 서명 키를 만든다. 발급된 토큰은 재시작 후 무효가 된다.
const signingKey = {
  ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }),
  kid: `es256-${Date.now()}`,
  alg: 'ES256',
  use: 'sig',
};

const configuration: Configuration = {
  jwks: { keys: [signingKey] },
  // 키가 ES256 하나뿐이라 동적 등록 클라이언트의 ID 토큰 기본 알고리즘도 맞춘다.
  clientDefaults: { id_token_signed_response_alg: 'ES256' },
  scopes: ['openid', 'offline_access', 'mcp:read'],
  async findAccount(_ctx, id) {
    const account = findSampleAccount(id);
    if (!account) return undefined;
    return {
      accountId: id,
      claims: () => ({ sub: id, tenant_id: account.tenantId }),
    };
  },
  features: {
    devInteractions: { enabled: true },
    // MCP 클라이언트(Inspector 등)가 스스로 등록할 수 있게 동적 등록을 연다.
    registration: { enabled: true },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => MCP_RESOURCE_URL,
      useGrantedResource: () => true,
      getResourceServerInfo(_ctx, resource) {
        if (resource !== MCP_RESOURCE_URL) throw new errors.InvalidTarget();
        return {
          scope: 'mcp:read',
          audience: MCP_RESOURCE_URL,
          accessTokenTTL: 15 * 60,
          accessTokenFormat: 'jwt',
          jwt: { sign: { alg: 'ES256' } },
        };
      },
    },
  },
  // Rust 쪽은 tenant_id 클레임이 없는 토큰을 거부한다.
  extraTokenClaims(_ctx: KoaContextWithOIDC, token) {
    const accountId = 'accountId' in token ? token.accountId : undefined;
    const tenantId = accountId ? findSampleAccount(accountId)?.tenantId : undefined;
    return tenantId ? { tenant_id: tenantId } : undefined;
  },
  pkce: { required: () => true },
  ttl: {
    AuthorizationCode: 60,
    // DCR 클라이언트가 refresh_token grant를 요청하면 발급된다. 기본값(14일)보다 짧게 둔다.
    RefreshToken: 24 * 60 * 60,
  },
};

const provider = new Provider(ISSUER, configuration);

// 로그인 폼은 짧은 urlencoded 본문뿐이다. 다른 형식은 oidc-provider가 직접 거부한다.
const MAX_INTERACTION_BODY = 16 * 1024;

// devInteractions는 아무 이름으로나 로그인시킨다. 샘플 계정이 아니면 세션에 남기기 전에 막는다.
// (계정 없는 세션은 oidc-provider 동의 단계에서 500을 낸다)
provider.use(async (ctx, next) => {
  if (
    ctx.method !== 'POST' ||
    !/^\/interaction\/[^/]+$/.test(ctx.path) ||
    !ctx.is('application/x-www-form-urlencoded')
  ) {
    return next();
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of ctx.req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_INTERACTION_BODY) ctx.throw(413);
    chunks.push(chunk);
  }
  const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));

  if (body.prompt === 'login' && !findSampleAccount(body.login ?? '')) {
    // 같은 인터랙션의 로그인 화면으로 돌아갈 수 있게 링크를 준다.
    const back = escapeHtml(ctx.path);
    const names = Object.keys(ACCOUNTS).join(', ');
    ctx.status = 403;
    ctx.type = 'html';
    ctx.body = `<p>등록되지 않은 계정입니다. 샘플 계정: ${names}</p><p><a href="${back}">다시 로그인</a></p>`;
    return;
  }
  // 이미 읽은 본문은 oidc-provider가 req.body로 이어받는다.
  Object.assign(ctx.req, { body });
  return next();
});

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

provider.listen(PORT, () => {
  console.log(`issuer ${ISSUER} (resource ${MCP_RESOURCE_URL})`);
});
