use auth_common::Principal;
use axum::http::request::Parts;
use rmcp::handler::server::common::Extension;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct SampleServer;

#[derive(Serialize, JsonSchema)]
pub struct WhoAmI {
    sub: String,
    tenant_id: String,
    scopes: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct EchoArgs {
    /// 그대로 돌려받을 문자열
    message: String,
}

#[tool_router(server_handler)]
impl SampleServer {
    #[tool(description = "현재 토큰의 사용자와 테넌트 정보를 반환한다")]
    async fn whoami(&self, Extension(parts): Extension<Parts>) -> Result<Json<WhoAmI>, ErrorData> {
        let p = principal(&parts)?;
        Ok(Json(WhoAmI {
            sub: p.sub.clone(),
            tenant_id: p.tenant_id.clone(),
            scopes: p.scopes.clone(),
        }))
    }

    #[tool(description = "입력한 문자열을 테넌트 ID와 함께 돌려준다")]
    async fn echo(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(args): Parameters<EchoArgs>,
    ) -> Result<String, ErrorData> {
        let p = principal(&parts)?;
        Ok(format!("[{}] {}", p.tenant_id, args.message))
    }
}

/// 인증 미들웨어가 넣어둔 호출자. 없으면 미들웨어를 거치지 않은 요청이다.
fn principal(parts: &Parts) -> Result<&Principal, ErrorData> {
    parts
        .extensions
        .get::<Principal>()
        .ok_or_else(|| ErrorData::internal_error("missing principal", None))
}
