//! MCP 인증 스펙의 리소스 서버 쪽: Bearer 검증과 보호 리소스 메타데이터(RFC 9728).

use std::sync::Arc;

use auth_common::{AuthError, Verifier};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Clone)]
pub struct AuthState {
    pub verifier: Arc<Verifier>,
    /// 401 응답의 `WWW-Authenticate`에 실어 보낼 메타데이터 URL
    pub metadata_url: String,
}

impl AuthState {
    pub fn new(verifier: Verifier) -> Self {
        let metadata_url = metadata_url(&verifier.config().audience);
        Self {
            verifier: Arc::new(verifier),
            metadata_url,
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
            let challenge = match e {
                AuthError::MissingToken => {
                    format!(r#"Bearer resource_metadata="{}""#, state.metadata_url)
                }
                _ => format!(
                    r#"Bearer error="invalid_token", resource_metadata="{}""#,
                    state.metadata_url
                ),
            };
            let mut res = StatusCode::UNAUTHORIZED.into_response();
            if let Ok(v) = HeaderValue::from_str(&challenge) {
                res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
            }
            res
        }
    }
}

pub async fn protected_resource_metadata(State(state): State<AuthState>) -> impl IntoResponse {
    let config = state.verifier.config();
    Json(json!({
        "resource": config.audience,
        "authorization_servers": [config.issuer],
        "bearer_methods_supported": ["header"],
    }))
}

/// `https://host/mcp` → `https://host/.well-known/oauth-protected-resource/mcp`
fn metadata_url(resource: &str) -> String {
    let after_scheme = resource.find("://").map_or(0, |i| i + 3);
    let (origin, path) = match resource[after_scheme..].find('/') {
        Some(i) => resource.split_at(after_scheme + i),
        None => (resource, ""),
    };
    format!(
        "{origin}/.well-known/oauth-protected-resource{}",
        path.trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::metadata_url;

    #[test]
    fn builds_metadata_url_from_resource() {
        assert_eq!(
            metadata_url("https://mcp.example.com/mcp"),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            metadata_url("http://localhost:3000"),
            "http://localhost:3000/.well-known/oauth-protected-resource"
        );
    }
}
