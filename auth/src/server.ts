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
    const account = ACCOUNTS[id];
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
    const tenantId = accountId ? ACCOUNTS[accountId]?.tenantId : undefined;
    return tenantId ? { tenant_id: tenantId } : undefined;
  },
  pkce: { required: () => true },
  ttl: { AuthorizationCode: 60 },
};

const provider = new Provider(ISSUER, configuration);
provider.listen(PORT, () => {
  console.log(`issuer ${ISSUER} (resource ${MCP_RESOURCE_URL})`);
});
