//! TS 인가 서버(oidc-provider)가 발급한 액세스 토큰(JWT)을 검증한다.
//! MCP 서버와 API Gateway authorizer가 같은 규칙을 쓰도록 공용 crate로 둔다.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::{Mutex, MutexGuard, RwLock};

/// 서명 알고리즘 허용 목록. HS*(대칭키)와 none은 받지 않는다.
const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::EdDSA,
];

/// JWKS 재조회 최소 간격. 알 수 없는 kid나 조회 실패가 인가 서버 호출 폭주로 이어지지 않게 막는다.
/// 키 교체 직후에는 이 시간만큼 새 키를 모를 수 있다.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// 이보다 오래된 JWKS는 다시 받는다. 인가 서버에서 빠진(폐기된) 키를 계속 신뢰하지 않게 한다.
const JWKS_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// 인가 서버 장애로 갱신하지 못할 때 마지막으로 받은 키를 계속 쓸 수 있는 상한.
/// 이 시간이 지나면 폐기됐을 수 있는 키를 더는 신뢰하지 않고 503으로 실패한다.
const MAX_STALE_AGE: Duration = Duration::from_secs(60 * 60);

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
    /// JWKS 주소를 직접 지정할 때만 쓴다. 없으면 issuer의 discovery 문서에서 찾는다.
    pub jwks_uri: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{0} must be an absolute http(s) URL, got {1:?}")]
    InvalidUrl(&'static str, String),
    #[error("{0} must use https unless the host is localhost, got {1:?}")]
    Insecure(&'static str, String),
}

impl VerifierConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let jwks_uri = match std::env::var("AUTH_JWKS_URI") {
            Ok(v) if !v.trim().is_empty() => Some(validate_url("AUTH_JWKS_URI", v)?),
            _ => None,
        };
        Ok(Self {
            issuer: url_var("AUTH_ISSUER")?,
            audience: url_var("MCP_RESOURCE_URL")?,
            jwks_uri,
        })
    }
}

fn url_var(name: &'static str) -> Result<String, ConfigError> {
    let value = std::env::var(name).map_err(|_| ConfigError::Missing(name))?;
    validate_url(name, value)
}

/// 스킴이 빠지거나 헤더에 실을 수 없는 문자가 있으면 메타데이터 URL과 Host 허용 목록이
/// 조용히 망가지므로 시작할 때 거부한다. 국제화 도메인은 punycode로 적는다.
/// 키와 토큰이 오가는 주소라 로컬 개발(localhost)이 아니면 https만 받는다.
fn validate_url(name: &'static str, value: String) -> Result<String, ConfigError> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    let printable = value.bytes().all(|b| b.is_ascii_graphic());
    match rest {
        Some(rest) if printable && !rest.is_empty() && !rest.starts_with(['/', '?', '#']) => {}
        _ => return Err(ConfigError::InvalidUrl(name, value)),
    }
    if !is_secure_url(&value) {
        return Err(ConfigError::Insecure(name, value));
    }
    Ok(value)
}

/// https이거나, 루프백 호스트의 http인가.
fn is_secure_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "https" => parsed.host().is_some(),
        "http" => {
            url_host(url).is_some_and(|h| matches!(h.as_str(), "localhost" | "127.0.0.1" | "::1"))
        }
        _ => false,
    }
}

/// URL의 호스트(소문자). 사용자 정보와 포트는 뺀다.
/// 실제로 연결할 호스트와 같아야 하므로 HTTP 클라이언트와 같은 WHATWG 파서로 읽는다.
/// `https://api.example.com:8443/prod/mcp` → `api.example.com`, `http://[::1]:3000` → `::1`
pub fn url_host(url: &str) -> Option<String> {
    let host = reqwest::Url::parse(url).ok()?.host()?.to_string();
    Some(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
    )
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

/// 빈 테넌트는 "테넌트 미지정" 데이터와 맞물릴 수 있어 거부한다.
fn principal_from(claims: Claims) -> Result<Principal, AuthError> {
    if claims.sub.trim().is_empty() || claims.tenant_id.trim().is_empty() {
        return Err(AuthError::InvalidToken("empty sub or tenant_id".into()));
    }
    Ok(Principal {
        sub: claims.sub,
        tenant_id: claims.tenant_id,
        scopes: claims.scope.split_whitespace().map(String::from).collect(),
    })
}

/// `at+jwt` 또는 `application/at+jwt` (대소문자 무시)
fn is_access_token_typ(typ: &str) -> bool {
    let typ = typ.strip_prefix("application/").unwrap_or(typ);
    typ.eq_ignore_ascii_case("at+jwt")
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

/// JWKS의 키 하나와, 그 키로 검증해도 되는 알고리즘.
#[derive(Clone)]
struct CachedKey {
    key: DecodingKey,
    algs: Vec<Algorithm>,
}

/// RFC 7518 §3.3: RS256·PS256 키는 2048비트 이상이어야 한다.
const MIN_RSA_BITS: usize = 2048;

/// base64url로 적힌 RSA 모듈러스 `n`의 실제 비트 수. 앞에 채운 0 바이트는 세지 않는다.
fn rsa_modulus_bits(n: &str) -> usize {
    use base64::Engine;
    let Ok(bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(n.trim_end_matches('='))
    else {
        return 0;
    };
    match bytes.iter().position(|b| *b != 0) {
        Some(i) => (bytes.len() - i) * 8 - bytes[i].leading_zeros() as usize,
        None => 0,
    }
}

/// 키 종류로 가능한 알고리즘을 정하고, JWK에 `alg`가 있으면 그 하나로 좁힌다.
/// 토큰 헤더의 `alg`는 공격자가 고를 수 있으므로 검증 알고리즘은 키 쪽에서 정한다.
fn key_algs(jwk: &Jwk) -> Vec<Algorithm> {
    let by_type: &[Algorithm] = match &jwk.algorithm {
        AlgorithmParameters::RSA(p) if rsa_modulus_bits(&p.n) >= MIN_RSA_BITS => {
            &[Algorithm::RS256, Algorithm::PS256]
        }
        AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
            &[Algorithm::ES256]
        }
        AlgorithmParameters::OctetKeyPair(p) if p.curve == EllipticCurve::Ed25519 => {
            &[Algorithm::EdDSA]
        }
        _ => &[],
    };
    match jwk.common.key_algorithm {
        None => by_type.to_vec(),
        Some(declared) => match Algorithm::try_from(declared) {
            Ok(alg) if by_type.contains(&alg) => vec![alg],
            _ => Vec::new(),
        },
    }
}

/// 검증에 쓸 수 있는 서명 키만 kid → CachedKey로 모은다.
/// 같은 kid가 두 번 나오면 먼저 나온 키를 쓰고 경고한다. 다른 키로 서명한 토큰은 서명 검증에서 걸러진다.
fn usable_keys(set: &JwkSet) -> HashMap<String, CachedKey> {
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        if jwk.common.public_key_use == Some(PublicKeyUse::Encryption) {
            continue;
        }
        let Some(kid) = jwk.common.key_id.clone() else {
            continue;
        };
        let algs = key_algs(jwk);
        let key = match DecodingKey::from_jwk(jwk) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(%kid, error = %e, "jwks key skipped: cannot be parsed");
                continue;
            }
        };
        if algs.is_empty() {
            tracing::warn!(%kid, "jwks key skipped: unsupported or weak key");
            continue;
        }
        if keys.contains_key(&kid) {
            tracing::warn!(%kid, "jwks has duplicate kid, keeping the first key");
            continue;
        }
        keys.insert(kid, CachedKey { key, algs });
    }
    keys
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, CachedKey>,
    /// 마지막으로 JWKS를 성공적으로 받은 시각
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
    last_error: Option<String>,
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
                // 리다이렉트로 검증한 주소 밖에서 키를 받아오지 않는다.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
            cache: RwLock::default(),
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    /// `Authorization` 헤더 값에서 Bearer 토큰을 꺼내 검증한다. 스킴은 대소문자를 구분하지 않는다.
    pub async fn verify_header(&self, header: Option<&str>) -> Result<Principal, AuthError> {
        let token = header
            .and_then(|h| h.trim().split_once(char::is_whitespace))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
            .filter(|t| !t.is_empty())
            .ok_or(AuthError::MissingToken)?;
        self.verify(token).await
    }

    pub async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(AuthError::InvalidToken(format!(
                "alg {:?} not allowed",
                header.alg
            )));
        }
        // RFC 9068 §4: ID 토큰 등 다른 용도의 JWT를 액세스 토큰으로 받지 않는다.
        if !header.typ.as_deref().is_some_and(is_access_token_typ) {
            return Err(AuthError::InvalidToken(format!(
                "typ {:?} is not at+jwt",
                header.typ
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("missing kid".into()))?;
        let key = self.decoding_key(&kid).await?;
        if !key.algs.contains(&header.alg) {
            return Err(AuthError::InvalidToken(format!(
                "alg {:?} does not match key {kid}",
                header.alg
            )));
        }

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;

        let data = decode::<Claims>(token, &key.key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        principal_from(data.claims)
    }

    async fn decoding_key(&self, kid: &str) -> Result<CachedKey, AuthError> {
        let (cached, age) = {
            let cache = self.cache.read().await;
            (
                cache.keys.get(kid).cloned(),
                cache.fetched_at.map(|at| at.elapsed()),
            )
        };
        if let Some(key) = &cached
            && age.is_some_and(|age| age <= JWKS_MAX_AGE)
        {
            return Ok(key.clone());
        }
        // 갱신이 안 될 때 대신 쓸 수 있는 키. 마지막 성공 후 MAX_STALE_AGE까지만 허용한다.
        let fallback = cached.filter(|_| age.is_some_and(|age| age < MAX_STALE_AGE));
        let refreshed = match (&fallback, self.refresh_lock.try_lock()) {
            (_, Ok(guard)) => self.refresh_locked(guard).await,
            // 대신 쓸 키가 있으면 다른 요청이 진행 중인 갱신을 기다리지 않는다.
            (Some(key), Err(_)) => return Ok(key.clone()),
            (None, Err(_)) => self.refresh().await,
        };
        if let Err(e) = refreshed {
            // 인가 서버 장애 중에는 이미 알던 키로 상한 시간까지 검증한다.
            return match fallback {
                Some(key) => {
                    tracing::warn!(error = %e, "jwks refresh failed, using cached key");
                    Ok(key)
                }
                None => Err(e),
            };
        }
        self.cache
            .read()
            .await
            .keys
            .get(kid)
            .cloned()
            .ok_or(AuthError::UnknownKey)
    }

    /// 키 교체(kid 변경)를 따라가기 위해 JWKS를 다시 받는다.
    /// 동시 요청은 한 번만 조회하고, 최근 시도가 있으면 그 결과(실패 포함)를 재사용한다.
    async fn refresh(&self) -> Result<(), AuthError> {
        let guard = self.refresh_lock.lock().await;
        self.refresh_locked(guard).await
    }

    async fn refresh_locked(&self, _guard: MutexGuard<'_, ()>) -> Result<(), AuthError> {
        {
            let cache = self.cache.read().await;
            if cache
                .last_attempt
                .is_some_and(|at| at.elapsed() < MIN_REFRESH_INTERVAL)
            {
                return match &cache.last_error {
                    Some(e) => Err(AuthError::Jwks(e.clone())),
                    None => Ok(()),
                };
            }
        }

        let result = self.fetch_keys().await;
        let mut cache = self.cache.write().await;
        cache.last_attempt = Some(Instant::now());
        match result {
            Ok(keys) => {
                tracing::info!(count = keys.len(), "jwks refreshed");
                cache.keys = keys;
                cache.fetched_at = cache.last_attempt;
                cache.last_error = None;
                Ok(())
            }
            Err(e) => {
                cache.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// 서명용 키만 골라 kid → DecodingKey로 미리 변환해 둔다. 쓸 수 있는 알고리즘이 없는 키는 버린다.
    async fn fetch_keys(&self) -> Result<HashMap<String, CachedKey>, AuthError> {
        let jwks_uri = match &self.config.jwks_uri {
            Some(uri) => uri.clone(),
            None => self.discover_jwks_uri().await?,
        };
        let set: JwkSet = self.get_json(&jwks_uri).await?;
        Ok(usable_keys(&set))
    }

    /// discovery 문서에서 JWKS 주소를 찾는다. 응답이 바뀌어도 키를 다른 곳에서 받아오지 않도록
    /// https(또는 localhost)이고 issuer와 같은 호스트인 주소만 받는다.
    async fn discover_jwks_uri(&self) -> Result<String, AuthError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: Discovery = self.get_json(&discovery_url).await?;
        // OIDC Discovery 1.0 §4.3: 응답의 issuer는 요청한 issuer와 정확히 같아야 한다.
        // 토큰 iss 검증도 정확히 비교하므로, 끝의 `/`만 다른 설정은 여기서 원인과 함께 드러난다.
        if discovery.issuer != self.config.issuer {
            return Err(AuthError::Jwks(format!(
                "discovery issuer mismatch: expected {}, got {}",
                self.config.issuer, discovery.issuer
            )));
        }
        let same_host = url_host(&discovery.jwks_uri)
            .zip(url_host(&self.config.issuer))
            .is_some_and(|(jwks, issuer)| jwks == issuer);
        if !is_secure_url(&discovery.jwks_uri) || !same_host {
            return Err(AuthError::Jwks(format!(
                "untrusted jwks_uri {} (must be https on the issuer host; set AUTH_JWKS_URI to override)",
                discovery.jwks_uri
            )));
        }
        Ok(discovery.jwks_uri)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use jsonwebtoken::{EncodingKey, Header, encode};
    use p256::SecretKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// 헤더 파싱 단계에서 끝나는 테스트용. 네트워크에 닿지 않는다.
    fn verifier() -> Verifier {
        Verifier::new(VerifierConfig {
            issuer: "http://unused.invalid".into(),
            audience: "http://localhost/mcp".into(),
            jwks_uri: None,
        })
    }

    #[tokio::test]
    async fn rejects_non_bearer_schemes() {
        let v = verifier();
        for h in [
            None,
            Some(""),
            Some("Basic abc"),
            Some("Bearer "),
            Some("Bearer"),
        ] {
            assert!(
                matches!(v.verify_header(h).await, Err(AuthError::MissingToken)),
                "{h:?}"
            );
        }
    }

    #[tokio::test]
    async fn accepts_bearer_scheme_case_insensitively() {
        let v = verifier();
        for h in ["Bearer x", "BEARER x", "bearer\tx"] {
            // 스킴은 통과하고 토큰 파싱 단계에서 실패해야 한다.
            assert!(
                matches!(
                    v.verify_header(Some(h)).await,
                    Err(AuthError::InvalidToken(_))
                ),
                "{h}"
            );
        }
    }

    fn unsigned_token(header: &str) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{}.{}.sig", b64.encode(header), b64.encode("{}"))
    }

    #[tokio::test]
    async fn rejects_tokens_that_are_not_access_tokens() {
        let v = verifier();
        for typ in [r#""typ":"JWT","#, ""] {
            let token = unsigned_token(&format!(r#"{{"alg":"ES256",{typ}"kid":"k"}}"#));
            let err = v.verify(&token).await.unwrap_err();
            assert!(
                matches!(&err, AuthError::InvalidToken(m) if m.contains("typ")),
                "{err}"
            );
        }
        assert!(is_access_token_typ("at+jwt"));
        assert!(is_access_token_typ("application/AT+JWT"));
    }

    #[test]
    fn rejects_empty_subject_or_tenant() {
        let claims = |sub: &str, tenant: &str| Claims {
            sub: sub.into(),
            tenant_id: tenant.into(),
            scope: "mcp:read".into(),
        };
        assert!(principal_from(claims("alice", "tenant-a")).is_ok());
        assert!(principal_from(claims("alice", " ")).is_err());
        assert!(principal_from(claims("", "tenant-a")).is_err());
    }

    #[test]
    fn validates_config_urls() {
        for ok in ["http://localhost:4000", "https://auth.example.com/tenant/x"] {
            assert!(validate_url("X", ok.into()).is_ok(), "{ok}");
        }
        for bad in [
            "auth.example.com",
            "https://",
            "https:///path",
            "https://인증.example.com",
            "https://auth.example.com ",
            "ftp://auth.example.com",
            "http://auth.example.com",
            "http://localhost.example.com",
            "http://evil.com\\@localhost:4000",
            "http://evil.com\\@localhost:3000/mcp",
        ] {
            assert!(validate_url("X", bad.into()).is_err(), "{bad}");
        }
        for local in ["http://127.0.0.1:4000/x", "http://[::1]:4000"] {
            assert!(validate_url("X", local.into()).is_ok(), "{local}");
        }
    }

    #[tokio::test]
    async fn rejects_jwks_uri_outside_issuer_or_via_redirect() {
        for jwks in ["https://keys.attacker.example/jwks", "/redirect"] {
            let issuer = issuer_full(None, None, Some(jwks)).await;
            let err = issuer
                .verifier()
                .verify(&issuer.token(serde_json::json!({})))
                .await;
            assert!(matches!(err, Err(AuthError::Jwks(_))), "{jwks}: {err:?}");
        }
    }

    #[tokio::test]
    async fn configured_jwks_uri_skips_discovery() {
        // discovery가 엉뚱한 jwks_uri를 알려줘도, 직접 지정한 주소에서 키를 받는다.
        let issuer = issuer_full(None, None, Some("https://keys.attacker.example/jwks")).await;
        let v = Verifier::new(VerifierConfig {
            issuer: issuer.base.clone(),
            audience: AUD.into(),
            jwks_uri: Some(format!("{}/jwks", issuer.base)),
        });
        assert!(v.verify(&issuer.token(serde_json::json!({}))).await.is_ok());
    }

    type Respond = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

    /// 경로별로 응답을 정하는 로컬 HTTP 서버. 받은 요청 수를 센다.
    async fn serve(respond: impl FnOnce(&str) -> Respond) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let respond = respond(&base);
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                let (status, body) = respond(path);
                // 302 응답이면 body를 Location으로 쓴다.
                let res = if status == 302 {
                    format!(
                        "HTTP/1.1 302 X\r\nlocation: {body}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                } else {
                    format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = socket.write_all(res.as_bytes()).await;
            }
        });
        (base, hits)
    }

    async fn failing_issuer() -> (String, Arc<AtomicUsize>) {
        serve(|_| Arc::new(|_| (500, String::new()))).await
    }

    /// 테스트마다 새로 만든 P-256 키로 서명하는 가짜 인가 서버.
    struct TestIssuer {
        base: String,
        signing: EncodingKey,
    }

    const AUD: &str = "http://localhost/mcp";

    async fn issuer_with(jwk_alg: Option<&str>, discovery_issuer: Option<&str>) -> TestIssuer {
        issuer_full(jwk_alg, discovery_issuer, None).await
    }

    /// `jwk_alg`가 Some이면 JWKS의 키에 그 alg를 적는다. `discovery_issuer`로 discovery의 issuer를,
    /// `jwks_path`로 discovery가 알려주는 jwks_uri를 바꾼다(`/`로 시작하면 같은 서버의 경로).
    /// `/redirect`는 `/jwks`로 302 리다이렉트한다.
    async fn issuer_full(
        jwk_alg: Option<&str>,
        discovery_issuer: Option<&str>,
        jwks_path: Option<&str>,
    ) -> TestIssuer {
        let secret = SecretKey::random(&mut OsRng);
        let der = secret.to_pkcs8_der().unwrap();
        let mut jwk: serde_json::Value =
            serde_json::from_str(&secret.public_key().to_jwk_string()).unwrap();
        jwk["kid"] = "k1".into();
        jwk["use"] = "sig".into();
        if let Some(alg) = jwk_alg {
            jwk["alg"] = alg.into();
        }
        let discovery_issuer = discovery_issuer.map(str::to_owned);
        let jwks_path = jwks_path.unwrap_or("/jwks").to_owned();
        let (base, _) = serve(move |base| {
            let base = base.to_owned();
            let issuer = discovery_issuer.unwrap_or_else(|| base.clone());
            let jwks_uri = match jwks_path.starts_with('/') {
                true => format!("{base}{jwks_path}"),
                false => jwks_path,
            };
            let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
            Arc::new(move |path| match path {
                "/.well-known/openid-configuration" => (
                    200,
                    serde_json::json!({ "issuer": issuer, "jwks_uri": jwks_uri }).to_string(),
                ),
                "/jwks" => (200, jwks.clone()),
                "/redirect" => (302, "/jwks".into()),
                _ => (404, "{}".into()),
            })
        })
        .await;
        TestIssuer {
            base,
            signing: EncodingKey::from_ec_der(der.as_bytes()),
        }
    }

    impl TestIssuer {
        fn verifier(&self) -> Verifier {
            Verifier::new(VerifierConfig {
                issuer: self.base.clone(),
                audience: AUD.into(),
                jwks_uri: None,
            })
        }

        /// oidc-provider가 발급하는 액세스 토큰과 같은 모양의 클레임. `patch`로 일부를 바꾼다.
        fn token(&self, patch: serde_json::Value) -> String {
            let now = jsonwebtoken::get_current_timestamp();
            let mut claims = serde_json::json!({
                "iss": self.base, "aud": AUD, "sub": "alice", "tenant_id": "tenant-a",
                "scope": "mcp:read", "iat": now, "exp": now + 600, "jti": "j1", "client_id": "c1",
            });
            for (k, v) in patch.as_object().unwrap() {
                claims[k] = v.clone();
            }
            let mut header = Header::new(Algorithm::ES256);
            header.typ = Some("at+jwt".into());
            header.kid = Some("k1".into());
            encode(&header, &claims, &self.signing).unwrap()
        }
    }

    #[tokio::test]
    async fn accepts_valid_signed_access_token() {
        let issuer = issuer_with(None, None).await;
        let p = issuer
            .verifier()
            .verify(&issuer.token(serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(
            (p.sub.as_str(), p.tenant_id.as_str()),
            ("alice", "tenant-a")
        );
        assert_eq!(p.scopes, ["mcp:read"]);
    }

    #[tokio::test]
    async fn rejects_signed_tokens_with_wrong_claims() {
        let issuer = issuer_with(None, None).await;
        let v = issuer.verifier();
        let now = jsonwebtoken::get_current_timestamp();
        for patch in [
            serde_json::json!({ "aud": "http://other/mcp" }),
            serde_json::json!({ "iss": "http://other-issuer" }),
            serde_json::json!({ "exp": now - 3600 }),
            serde_json::json!({ "nbf": now + 3600 }),
        ] {
            let token = issuer.token(patch.clone());
            assert!(
                matches!(v.verify(&token).await, Err(AuthError::InvalidToken(_))),
                "{patch}"
            );
        }
        // 같은 kid·iss를 쓰지만 다른 키로 서명한 위조 토큰
        let attacker = issuer_with(None, None).await;
        let forged = TestIssuer {
            base: issuer.base.clone(),
            signing: attacker.signing,
        }
        .token(serde_json::json!({}));
        assert!(matches!(
            v.verify(&forged).await,
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[tokio::test]
    async fn header_alg_must_match_key() {
        let issuer = issuer_with(None, None).await;
        let v = issuer.verifier();
        v.refresh().await.unwrap();
        // EC 키에 RS256을 주장하는 토큰. 서명 검증 전에 알고리즘 불일치로 거부한다.
        let token = unsigned_token(r#"{"alg":"RS256","typ":"at+jwt","kid":"k1"}"#);
        let err = v.verify(&token).await.unwrap_err();
        assert!(
            matches!(&err, AuthError::InvalidToken(m) if m.contains("does not match")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn key_with_mismatched_declared_alg_is_ignored() {
        // P-256 키인데 JWK가 RS256이라고 적은 경우 그 키는 쓰지 않는다.
        let issuer = issuer_with(Some("RS256"), None).await;
        let token = issuer.token(serde_json::json!({}));
        assert!(matches!(
            issuer.verifier().verify(&token).await,
            Err(AuthError::UnknownKey)
        ));
    }

    /// 최상위 비트가 1인 `bits`비트 모듈러스. 앞에 `zero_pad`바이트의 0을 붙일 수 있다.
    fn rsa_n(bits: usize, zero_pad: usize) -> String {
        use base64::Engine;
        let mut n = vec![0u8; zero_pad];
        n.push(0x80);
        n.resize(zero_pad + bits / 8, 0x01);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n)
    }

    fn rsa_jwk(kid: &str, n_bytes: usize) -> serde_json::Value {
        serde_json::json!({ "kty": "RSA", "kid": kid, "e": "AQAB", "n": rsa_n(n_bytes * 8, 0) })
    }

    #[test]
    fn rsa_modulus_bits_ignores_zero_padding() {
        assert_eq!(rsa_modulus_bits(&rsa_n(2048, 0)), 2048);
        // 1024비트 키 앞에 0을 128바이트 채워도 1024비트로 센다.
        assert_eq!(rsa_modulus_bits(&rsa_n(1024, 128)), 1024);
        assert_eq!(rsa_modulus_bits("not base64!"), 0);
    }

    #[test]
    fn weak_rsa_keys_are_skipped() {
        let set: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [rsa_jwk("weak", 1024 / 8), rsa_jwk("ok", 2048 / 8)]
        }))
        .unwrap();
        let keys = usable_keys(&set);
        assert!(!keys.contains_key("weak"));
        assert_eq!(keys["ok"].algs, [Algorithm::RS256, Algorithm::PS256]);
    }

    #[test]
    fn duplicate_kid_keeps_first_key() {
        let mut first = rsa_jwk("dup", 2048 / 8);
        first["alg"] = "RS256".into();
        let mut second = rsa_jwk("dup", 2048 / 8);
        second["alg"] = "PS256".into();
        let set: JwkSet =
            serde_json::from_value(serde_json::json!({ "keys": [first, second] })).unwrap();
        assert_eq!(usable_keys(&set)["dup"].algs, [Algorithm::RS256]);
    }

    #[tokio::test]
    async fn issuer_must_match_exactly() {
        // 설정은 끝에 `/`가 없고 discovery는 `/`가 붙은 경우: 원인을 담은 오류로 실패한다.
        let base = issuer_with(None, None).await.base;
        let issuer = issuer_with(None, Some(&format!("{base}/"))).await;
        let err = issuer
            .verifier()
            .verify(&issuer.token(serde_json::json!({})))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AuthError::Jwks(m) if m.contains("issuer mismatch")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn failed_jwks_fetch_is_not_retried_immediately() {
        let (issuer, hits) = failing_issuer().await;
        let v = Verifier::new(VerifierConfig {
            issuer,
            audience: AUD.into(),
            jwks_uri: None,
        });
        assert!(matches!(v.refresh().await, Err(AuthError::Jwks(_))));
        assert!(matches!(v.refresh().await, Err(AuthError::Jwks(_))));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    async fn verifier_with_cached_key(issuer: String, age: Duration) -> Verifier {
        let v = Verifier::new(VerifierConfig {
            issuer,
            audience: AUD.into(),
            jwks_uri: None,
        });
        let mut cache = v.cache.write().await;
        cache.keys.insert(
            "known".into(),
            CachedKey {
                key: DecodingKey::from_secret(b"s"),
                algs: vec![Algorithm::ES256],
            },
        );
        cache.fetched_at = Instant::now().checked_sub(age);
        drop(cache);
        v
    }

    #[tokio::test]
    async fn stale_cached_key_is_used_while_issuer_is_down() {
        let (issuer, hits) = failing_issuer().await;
        let v = verifier_with_cached_key(issuer, JWKS_MAX_AGE + Duration::from_secs(60)).await;
        assert!(v.decoding_key("known").await.is_ok());
        assert!(matches!(
            v.decoding_key("unknown").await,
            Err(AuthError::Jwks(_))
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cached_key_is_not_used_past_max_stale_age() {
        let (issuer, _) = failing_issuer().await;
        let v = verifier_with_cached_key(issuer, MAX_STALE_AGE + Duration::from_secs(60)).await;
        assert!(matches!(
            v.decoding_key("known").await,
            Err(AuthError::Jwks(_))
        ));
    }

    #[tokio::test]
    async fn stale_cached_key_does_not_wait_for_running_refresh() {
        let v = verifier_with_cached_key(
            "http://unused.invalid".into(),
            JWKS_MAX_AGE + Duration::from_secs(60),
        )
        .await;
        // 다른 요청이 갱신 중인 상황
        let _running = v.refresh_lock.lock().await;
        let result =
            tokio::time::timeout(Duration::from_millis(200), v.decoding_key("known")).await;
        assert!(matches!(result, Ok(Ok(_))));
    }
}
