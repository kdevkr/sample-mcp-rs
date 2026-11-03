//! API Gateway(HTTP API) Lambda authorizer. simple response 형식을 쓴다.
//! 검증 규칙은 MCP 서버와 같은 auth-common을 공유한다.
//!
//! `/mcp`와 `/.well-known/*` 라우트에는 붙이지 않는다. 거부 시 API Gateway가
//! `WWW-Authenticate` 없는 403을 돌려줘 MCP 클라이언트가 OAuth 탐색을 시작하지 못한다.
//! MCP 라우트는 mcp-server가 직접 검증하고, 이 authorizer는 그 밖의 API 라우트용이다.

use auth_common::{AuthError, Verifier, VerifierConfig};
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

    let mut res = ApiGatewayV2CustomAuthorizerSimpleResponse::default();
    match verifier.verify_header(header).await {
        Ok(p) => {
            res.is_authorized = true;
            res.context = json!({ "sub": p.sub, "tenant_id": p.tenant_id });
        }
        // 인가 서버 장애는 일반 거부와 구분해 알람을 걸 수 있게 한다.
        Err(AuthError::Jwks(e)) => tracing::error!(error = %e, "denied: jwks unavailable"),
        Err(e) => tracing::info!(error = %e, "denied"),
    }
    Ok(res)
}
