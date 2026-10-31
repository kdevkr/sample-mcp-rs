//! TS 인가 서버(oidc-provider)가 발급한 액세스 토큰(JWT)을 검증한다.
//! MCP 서버와 API Gateway authorizer가 같은 규칙을 쓰도록 공용 crate로 둔다.

use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

/// 서명 알고리즘 허용 목록. HS*(대칭키)와 none은 받지 않는다.
const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::EdDSA,
];

/// 알 수 없는 kid로 JWKS 재조회를 남발하지 못하게 막는 최소 간격.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("signing key not found")]
    UnknownKey,
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
}

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// 인가 서버 issuer (예: https://auth.example.com)
    pub issuer: String,
    /// 이 토큰을 받을 리소스 (MCP 서버 URL, RFC 8707 `resource`)
    pub audience: String,
}

impl VerifierConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            issuer: std::env::var("AUTH_ISSUER")?,
            audience: std::env::var("MCP_RESOURCE_URL")?,
        })
    }
}

/// 검증을 통과한 호출자. 테넌트 필터링은 이 값만 신뢰한다.
#[derive(Debug, Clone)]
pub struct Principal {
    pub sub: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    tenant_id: String,
    #[serde(default)]
    scope: String,
}

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

struct JwksCache {
    keys: JwkSet,
    fetched_at: Option<Instant>,
}

pub struct Verifier {
    config: VerifierConfig,
    http: reqwest::Client,
    cache: RwLock<JwksCache>,
    refresh_lock: Mutex<()>,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
            cache: RwLock::new(JwksCache {
                keys: JwkSet { keys: Vec::new() },
                fetched_at: None,
            }),
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    /// `Authorization` 헤더 값에서 Bearer 토큰을 꺼내 검증한다.
    pub async fn verify_header(&self, header: Option<&str>) -> Result<Principal, AuthError> {
        let token = header
            .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(AuthError::MissingToken)?;
        self.verify(token).await
    }

    pub async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(AuthError::InvalidToken(format!("alg {:?} not allowed", header.alg)));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("missing kid".into()))?;
        let key = self.decoding_key(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        let claims = data.claims;
        Ok(Principal {
            sub: claims.sub,
            tenant_id: claims.tenant_id,
            scopes: claims.scope.split_whitespace().map(String::from).collect(),
        })
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        if let Some(key) = self.cached_key(kid).await? {
            return Ok(key);
        }
        self.refresh().await?;
        self.cached_key(kid).await?.ok_or(AuthError::UnknownKey)
    }

    async fn cached_key(&self, kid: &str) -> Result<Option<DecodingKey>, AuthError> {
        let cache = self.cache.read().await;
        cache
            .keys
            .find(kid)
            .map(|jwk| DecodingKey::from_jwk(jwk).map_err(|e| AuthError::Jwks(e.to_string())))
            .transpose()
    }

    /// 키 교체(kid 변경)를 따라가기 위해 JWKS를 다시 받는다. 동시 요청은 한 번만 조회한다.
    async fn refresh(&self) -> Result<(), AuthError> {
        let _guard = self.refresh_lock.lock().await;
        if let Some(at) = self.cache.read().await.fetched_at
            && at.elapsed() < MIN_REFRESH_INTERVAL
        {
            return Ok(());
        }

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: Discovery = self.get_json(&discovery_url).await?;
        let keys: JwkSet = self.get_json(&discovery.jwks_uri).await?;
        tracing::info!(count = keys.keys.len(), "jwks refreshed");

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, AuthError> {
        self.http
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| AuthError::Jwks(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Jwks(e.to_string()))
    }
}
