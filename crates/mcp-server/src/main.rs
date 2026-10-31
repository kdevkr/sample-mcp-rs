mod auth;
mod tools;

use std::sync::Arc;

use auth_common::{Verifier, VerifierConfig};
use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::auth::{AuthState, protected_resource_metadata, require_bearer};
use crate::tools::SampleServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let auth = AuthState::new(Verifier::new(VerifierConfig::from_env()?));
    let app = router(auth, allowed_hosts());

    if std::env::var_os("AWS_LAMBDA_RUNTIME_API").is_some() {
        lambda_http::run(app).await.map_err(|e| anyhow::anyhow!(e))
    } else {
        let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
        tracing::info!("listening on http://{}/mcp", listener.local_addr()?);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

fn router(auth: AuthState, allowed_hosts: Vec<String>) -> Router {
    // Lambda는 인스턴스 간 세션을 공유할 수 없어 stateless로 고정한다.
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(allowed_hosts);
    let mcp = StreamableHttpService::new(
        || Ok(SampleServer),
        Arc::new(NeverSessionManager::default()),
        config,
    );

    let metadata = get(protected_resource_metadata);
    Router::new()
        .nest_service("/mcp", mcp)
        .route_layer(from_fn_with_state(auth.clone(), require_bearer))
        .route("/.well-known/oauth-protected-resource", metadata.clone())
        .route("/.well-known/oauth-protected-resource/mcp", metadata)
        .with_state(auth)
}

/// DNS 리바인딩 방지용 Host 허용 목록. 배포 시 실제 도메인을 넣는다.
fn allowed_hosts() -> Vec<String> {
    std::env::var("MCP_ALLOWED_HOSTS")
        .map(|v| v.split(',').map(|h| h.trim().to_owned()).collect())
        .unwrap_or_else(|_| vec!["localhost".into(), "127.0.0.1".into()])
}
