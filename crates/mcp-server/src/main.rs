mod auth;
mod tools;

use std::sync::Arc;

use auth_common::{Verifier, VerifierConfig, url_host};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::auth::{AuthState, protected_resource_metadata, require_bearer, split_resource};
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

    let config = VerifierConfig::from_env()?;
    let path = mcp_path(&config.audience)?;
    let hosts = allowed_hosts(&config.audience);
    let origins = allowed_origins()?;
    tracing::info!(%path, ?hosts, ?origins, "mcp endpoint");
    let app = router(AuthState::new(Verifier::new(config), &path), &path, hosts, origins);

    if std::env::var_os("AWS_LAMBDA_RUNTIME_API").is_some() {
        lambda_http::run(app).await.map_err(|e| anyhow::anyhow!(e))
    } else {
        // 컨테이너에서 띄울 때는 HOST=0.0.0.0으로 연다. 기본은 이 PC에서만 접속 가능하다.
        let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
        let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await?;
        tracing::info!("listening on http://{}{path}", listener.local_addr()?);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// MCP 엔드포인트 경로는 MCP_RESOURCE_URL의 경로를 그대로 쓴다. 토큰 `aud`와 실제 경로가 어긋나지 않게 한다.
/// 경로는 라우트 패턴으로 등록되므로 `{`, `*` 같은 패턴 문자가 섞이지 않게 문자를 제한한다.
fn mcp_path(resource: &str) -> anyhow::Result<String> {
    let path = split_resource(resource).1.trim_end_matches('/');
    anyhow::ensure!(
        !path.is_empty(),
        "MCP_RESOURCE_URL must include an endpoint path such as /mcp: {resource}"
    );
    let valid = path.split('/').skip(1).all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    });
    anyhow::ensure!(valid, "MCP_RESOURCE_URL path has unsupported characters: {path}");
    Ok(path.to_owned())
}

fn router(
    auth: AuthState,
    path: &str,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<HeaderValue>,
) -> Router {
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

    // 루트 경로와, 401 응답이 가리키는 리소스 경로(RFC 9728 접미사) 두 곳에만 응답한다.
    let metadata = get(protected_resource_metadata);
    let mut app = Router::new()
        .nest_service(path, mcp)
        .route_layer(from_fn_with_state(auth.clone(), require_bearer))
        .route("/.well-known/oauth-protected-resource", metadata.clone());
    if auth.metadata_path != "/.well-known/oauth-protected-resource" {
        app = app.route(&auth.metadata_path, metadata);
    }
    let mut app = app.with_state(auth);
    if !allowed_origins.is_empty() {
        // MCP Streamable HTTP 스펙: 허용하지 않은 Origin의 요청은 403으로 거부한다.
        let allowed: Arc<[HeaderValue]> = allowed_origins.clone().into();
        app = app.layer(from_fn_with_state(allowed, reject_unknown_origin));
    }
    // CORS는 가장 바깥에 둬서 브라우저의 preflight(OPTIONS)가 인증·Origin 검사 전에 처리되게 한다.
    app.layer(cors(allowed_origins))
}

/// Origin 헤더가 있는데 허용 목록에 없으면 403. Origin이 없는 요청(브라우저 밖 클라이언트)은 통과한다.
async fn reject_unknown_origin(
    State(allowed): State<Arc<[HeaderValue]>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(origin) = req.headers().get(header::ORIGIN)
        && !allowed
            .iter()
            .any(|a| a.as_bytes().eq_ignore_ascii_case(origin.as_bytes()))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

/// 브라우저 기반 MCP 클라이언트용. 허용 목록이 비어 있으면 모든 Origin을 허용한다.
/// 쿠키 없이 Bearer 토큰만 쓰므로 샘플에서는 괜찮지만, 운영에서는 MCP_ALLOWED_ORIGINS로 좁힌다.
fn cors(allowed_origins: Vec<HeaderValue>) -> CorsLayer {
    let mcp_header = |name| HeaderName::from_static(name);
    let origin = if allowed_origins.is_empty() {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(allowed_origins)
    };
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            mcp_header("mcp-protocol-version"),
            mcp_header("mcp-session-id"),
            mcp_header("last-event-id"),
        ])
        .expose_headers([header::WWW_AUTHENTICATE, mcp_header("mcp-session-id")])
}

/// 쉼표로 구분한 환경 변수 값. 빈 항목은 버린다.
fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 허용 Origin 목록 (예: `https://app.example.com,http://localhost:6274`).
/// 비어 있으면 모든 Origin을 허용한다.
fn allowed_origins() -> anyhow::Result<Vec<HeaderValue>> {
    env_list("MCP_ALLOWED_ORIGINS")
        .iter()
        .map(|origin| parse_origin(origin))
        .collect()
}

/// 브라우저가 보내는 Origin 형태(`scheme://host[:port]`, 소문자)로 맞춘다.
/// 경로·쿼리가 붙은 값은 어떤 Origin과도 일치하지 않아 조용히 차단되므로 시작할 때 거부한다.
fn parse_origin(value: &str) -> anyhow::Result<HeaderValue> {
    let origin = value.trim_end_matches('/').to_ascii_lowercase();
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    anyhow::ensure!(
        authority.is_some_and(|a| !a.is_empty() && !a.contains(['/', '?', '#', '@'])),
        "MCP_ALLOWED_ORIGINS entry must look like https://host[:port]: {value}"
    );
    Ok(HeaderValue::from_str(&origin)?)
}

/// DNS 리바인딩 방지용 Host 허용 목록.
/// 기본값은 MCP_RESOURCE_URL의 호스트와 루프백이라, 별도 설정 없이 배포 도메인이 허용된다.
/// MCP_ALLOWED_HOSTS가 비어 있으면 기본값을 쓴다.
fn allowed_hosts(resource: &str) -> Vec<String> {
    let configured = env_list("MCP_ALLOWED_HOSTS");
    if !configured.is_empty() {
        return configured;
    }
    let mut hosts = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    if let Some(host) = url_host(resource)
        && !hosts.contains(&host)
    {
        hosts.push(host);
    }
    hosts
}

#[cfg(test)]
mod tests {
    use auth_common::{Verifier, VerifierConfig};
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode, header};
    use tower::ServiceExt;

    use super::{AuthState, mcp_path, parse_origin, router, url_host};

    /// 인가 서버에 닿기 전에 끝나는 요청만 보내므로 issuer는 쓰이지 않는다.
    fn app_with_origins(origins: &[&str]) -> axum::Router {
        let verifier = Verifier::new(VerifierConfig {
            issuer: "http://unused.invalid".into(),
            audience: "http://localhost:3000/mcp".into(),
            jwks_uri: None,
        });
        let origins = origins.iter().map(|o| HeaderValue::from_str(o).unwrap()).collect();
        router(AuthState::new(verifier, "/mcp"), "/mcp", vec!["localhost".into()], origins)
    }

    fn app() -> axum::Router {
        app_with_origins(&[])
    }

    fn preflight(origin: &str) -> Request<Body> {
        Request::options("/mcp")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization,content-type")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn cors_allow_list_limits_origins() {
        let app = app_with_origins(&["https://app.example.com"]);
        let allowed = app.clone().oneshot(preflight("https://app.example.com")).await.unwrap();
        assert_eq!(
            allowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example.com"
        );
        let other = app.oneshot(preflight("https://evil.example.com")).await.unwrap();
        assert!(other.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    #[tokio::test]
    async fn mcp_without_token_gets_401_with_metadata_pointer() {
        let res = app()
            .oneshot(
                Request::post("/mcp")
                    .header(header::HOST, "localhost:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let challenge = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert_eq!(
            challenge,
            r#"Bearer resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/mcp""#
        );
    }

    fn post_mcp(origin: Option<&str>) -> Request<Body> {
        let mut req = Request::post("/mcp")
            .header(header::HOST, "localhost:3000")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        req.body(Body::from("{}")).unwrap()
    }

    #[tokio::test]
    async fn unknown_origin_is_rejected_when_allow_list_is_set() {
        let restricted = app_with_origins(&["https://app.example.com"]);
        for (origin, status) in [
            (Some("https://evil.example.com"), StatusCode::FORBIDDEN),
            // 허용된 Origin과 Origin 없는 요청은 인증 단계까지 간다.
            (Some("https://APP.example.com"), StatusCode::UNAUTHORIZED),
            (None, StatusCode::UNAUTHORIZED),
        ] {
            let res = restricted.clone().oneshot(post_mcp(origin)).await.unwrap();
            assert_eq!(res.status(), status, "{origin:?}");
        }
        // 허용 목록이 없으면 Origin으로 거부하지 않는다.
        let res = app().oneshot(post_mcp(Some("https://evil.example.com"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn parses_allowed_origins() {
        assert_eq!(parse_origin("https://App.Example.com/").unwrap(), "https://app.example.com");
        assert_eq!(parse_origin("http://localhost:6274").unwrap(), "http://localhost:6274");
        for bad in [
            "app.example.com",
            "https://app.example.com/path",
            "https://app.example.com?x=1",
            "https://user@app.example.com",
            "https://",
            "*",
        ] {
            assert!(parse_origin(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn cors_preflight_is_not_blocked_by_auth() {
        let res = app().oneshot(preflight("http://localhost:6274")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    }

    #[tokio::test]
    async fn serves_metadata_only_at_known_paths() {
        for (path, status) in [
            ("/.well-known/oauth-protected-resource", StatusCode::OK),
            ("/.well-known/oauth-protected-resource/mcp", StatusCode::OK),
            ("/.well-known/oauth-protected-resource/other", StatusCode::NOT_FOUND),
        ] {
            let res = app()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), status, "{path}");
        }
    }

    #[test]
    fn mcp_path_follows_resource_url() {
        assert_eq!(mcp_path("http://localhost:3000/mcp").unwrap(), "/mcp");
        assert_eq!(mcp_path("https://api.example.com/prod/mcp/").unwrap(), "/prod/mcp");
        assert_eq!(mcp_path("https://api.example.com/mcp?x=1").unwrap(), "/mcp");
    }

    #[test]
    fn mcp_path_rejects_missing_or_pattern_paths() {
        for bad in [
            "https://api.example.com",
            "https://api.example.com/",
            "https://api.example.com/{tenant}/mcp",
            "https://api.example.com/*rest",
            "https://api.example.com//mcp",
        ] {
            assert!(mcp_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn extracts_host_from_url() {
        assert_eq!(url_host("https://api.example.com/prod/mcp").as_deref(), Some("api.example.com"));
        assert_eq!(url_host("http://localhost:3000/mcp").as_deref(), Some("localhost"));
        assert_eq!(url_host("http://[::1]:3000/mcp").as_deref(), Some("::1"));
        assert_eq!(url_host("https://api.example.com?x=1").as_deref(), Some("api.example.com"));
        assert_eq!(url_host("https://api.example.com#f").as_deref(), Some("api.example.com"));
        assert_eq!(url_host("not a url").as_deref(), None);
        // WHATWG처럼 `\`를 `/`로 본다. 사용자 정보로 읽으면 실제 연결 호스트와 달라진다.
        assert_eq!(url_host("https://evil.com\\@auth.example.com/jwks").as_deref(), Some("evil.com"));
    }
}
