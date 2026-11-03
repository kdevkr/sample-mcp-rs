//! MCP 인증 스펙의 리소스 서버 쪽: Bearer 검증과 보호 리소스 메타데이터(RFC 9728).

use std::sync::Arc;

use auth_common::{AuthError, Verifier};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// MCP 도구 호출에 필요한 스코프. 인가 서버의 resource 스코프와 맞춘다.
const REQUIRED_SCOPE: &str = "mcp:read";

#[derive(Clone)]
pub struct AuthState {
    pub verifier: Arc<Verifier>,
    /// 401 응답의 `WWW-Authenticate`에 실어 보낼 메타데이터 URL
    pub metadata_url: String,
    /// 위 URL의 경로. 라우터가 이 경로에만 메타데이터를 응답한다.
    pub metadata_path: String,
}

impl AuthState {
    /// `mcp_path`는 main의 `mcp_path()`로 검증한 MCP 엔드포인트 경로다.
    pub fn new(verifier: Verifier, mcp_path: &str) -> Self {
        let origin = split_resource(&verifier.config().audience).0;
        let metadata_path = format!("/.well-known/oauth-protected-resource{mcp_path}");
        Self {
            metadata_url: format!("{origin}{metadata_path}"),
            metadata_path,
            verifier: Arc::new(verifier),
        }
    }
}

pub async fn require_bearer(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match state.verifier.verify_header(header).await {
        Ok(principal) if !principal.scopes.iter().any(|s| s == REQUIRED_SCOPE) => {
            // 스코프가 부족하면 403으로 알려 클라이언트가 스코프를 올려 다시 인가받게 한다.
            challenge(
                StatusCode::FORBIDDEN,
                format!(
                    r#"Bearer error="insufficient_scope", scope="{REQUIRED_SCOPE}", resource_metadata="{}""#,
                    state.metadata_url
                ),
            )
        }
        Ok(principal) => {
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Err(AuthError::Jwks(e)) => {
            tracing::error!(error = %e, "jwks unavailable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(e) => {
            tracing::debug!(error = %e, "unauthorized");
            let value = match e {
                AuthError::MissingToken => {
                    format!(r#"Bearer resource_metadata="{}""#, state.metadata_url)
                }
                _ => format!(
                    r#"Bearer error="invalid_token", resource_metadata="{}""#,
                    state.metadata_url
                ),
            };
            challenge(StatusCode::UNAUTHORIZED, value)
        }
    }
}

fn challenge(status: StatusCode, value: String) -> Response {
    let mut res = status.into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    res
}

pub async fn protected_resource_metadata(State(state): State<AuthState>) -> impl IntoResponse {
    let config = state.verifier.config();
    Json(json!({
        "resource": config.audience,
        "authorization_servers": [config.issuer],
        "scopes_supported": [REQUIRED_SCOPE],
        "bearer_methods_supported": ["header"],
    }))
}

/// 리소스 URL을 origin과 경로로 나눈다. 쿼리와 프래그먼트는 버린다.
/// `https://host:8443/prod/mcp?x=1` → (`https://host:8443`, `/prod/mcp`)
pub fn split_resource(resource: &str) -> (&str, &str) {
    let after_scheme = resource.find("://").map_or(0, |i| i + 3);
    let authority_end = resource[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(resource.len(), |i| after_scheme + i);
    let (origin, rest) = resource.split_at(authority_end);
    let path = rest.split(['?', '#']).next().unwrap_or_default();
    (origin, path)
}

#[cfg(test)]
mod tests {
    use super::split_resource;

    #[test]
    fn splits_resource_into_origin_and_path() {
        assert_eq!(
            split_resource("https://mcp.example.com/prod/mcp"),
            ("https://mcp.example.com", "/prod/mcp")
        );
        assert_eq!(split_resource("http://localhost:3000"), ("http://localhost:3000", ""));
        assert_eq!(
            split_resource("https://api.example.com?x=1#f"),
            ("https://api.example.com", "")
        );
        assert_eq!(
            split_resource("https://api.example.com/mcp?x=1"),
            ("https://api.example.com", "/mcp")
        );
    }
}
