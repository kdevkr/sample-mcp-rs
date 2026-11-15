//! API Gateway(HTTP API) Lambda authorizer. simple response 형식을 쓴다.
//! 검증 규칙은 MCP 서버와 같은 auth-common을 공유한다.
//!
//! `/mcp`와 `/.well-known/*` 라우트에는 붙이지 않는다. 거부 시 API Gateway가
//! `WWW-Authenticate` 없는 403을 돌려줘 MCP 클라이언트가 OAuth 탐색을 시작하지 못한다.
//! MCP 라우트는 mcp-server가 직접 검증하고, 이 authorizer는 같은 토큰을 받는 그 밖의 API 라우트용이다.
//! 토큰의 `aud`는 `MCP_RESOURCE_URL`이어야 하고 `mcp:read` 스코프가 있어야 한다.

use auth_common::{AuthError, Principal, REQUIRED_SCOPE, Verifier, VerifierConfig};
use aws_lambda_events::apigw::{
    ApiGatewayV2CustomAuthorizerSimpleResponse, ApiGatewayV2CustomAuthorizerV2Request,
};
use lambda_runtime::{Error, LambdaEvent, service_fn};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .init();

    // 콜드 스타트 때 한 번 만들고 JWKS 캐시를 호출 간에 재사용한다.
    let verifier = &*Box::leak(Box::new(Verifier::new(VerifierConfig::from_env()?)));
    lambda_runtime::run(service_fn(move |event| handler(verifier, event))).await
}

async fn handler(
    verifier: &Verifier,
    event: LambdaEvent<ApiGatewayV2CustomAuthorizerV2Request>,
) -> Result<ApiGatewayV2CustomAuthorizerSimpleResponse, Error> {
    let header = event
        .payload
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    Ok(decide(verifier.verify_header(header).await))
}

fn decide(result: Result<Principal, AuthError>) -> ApiGatewayV2CustomAuthorizerSimpleResponse {
    let mut res = ApiGatewayV2CustomAuthorizerSimpleResponse::default();
    match result {
        Ok(p) if !p.scopes.iter().any(|s| s == REQUIRED_SCOPE) => {
            tracing::info!(sub = %p.sub, "denied: insufficient scope");
        }
        Ok(p) => {
            res.is_authorized = true;
            res.context = json!({ "sub": p.sub, "tenant_id": p.tenant_id });
        }
        // 인가 서버 장애는 일반 거부와 구분해 알람을 걸 수 있게 한다.
        Err(AuthError::Jwks(e)) => tracing::error!(error = %e, "denied: jwks unavailable"),
        Err(e) => tracing::info!(error = %e, "denied"),
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(scopes: &[&str]) -> Principal {
        Principal {
            sub: "alice".into(),
            tenant_id: "tenant-a".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn allows_token_with_required_scope() {
        let res = decide(Ok(principal(&["openid", REQUIRED_SCOPE])));
        assert!(res.is_authorized);
        assert_eq!(
            res.context,
            json!({ "sub": "alice", "tenant_id": "tenant-a" })
        );
    }

    #[test]
    fn denies_without_scope_or_on_error() {
        for result in [
            Ok(principal(&[])),
            Ok(principal(&["openid"])),
            Err(AuthError::MissingToken),
            Err(AuthError::Jwks("down".into())),
        ] {
            let res = decide(result);
            assert!(!res.is_authorized);
            assert_eq!(res.context, serde_json::Value::Null);
        }
    }
}
