use super::*;
use crate::application::web::security::{
    limits::{SecurityPolicy, SecurityState},
    session::SessionManager,
    IpMatcher, TokenKey, WebRoute,
};
use crate::application::web::SESSION_COOKIE_NAME;
use axum::extract::ConnectInfo;
use axum::http::{header::AUTHORIZATION, header::COOKIE, request::Parts, Request, StatusCode};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use std::time::Instant;

fn make_parts(path: &str, ip: IpAddr, token: Option<&str>) -> Parts {
    let request = Request::builder().uri(path).body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    if let Some(token) = token {
        parts
            .headers
            .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    }
    parts
        .extensions
        .insert(ConnectInfo(std::net::SocketAddr::from((ip, 4242))));
    parts
}

fn argon2_hash(secret: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut rand_core::OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .expect("hash password")
        .to_string()
}

fn cached_argon2() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| argon2_hash("secret"))
}

#[tokio::test]
async fn verify_token_accepts_valid_bearer() {
    let state = SecurityState::new();
    let policy = SecurityPolicy::default();
    let sessions = SessionManager::new();
    let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
    let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), Some("secret"));
    let now = Instant::now();
    let request = build_request(
        &[],
        &[],
        &sessions,
        true,
        Some(verifier.fingerprint()),
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();

    verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
        .await
        .expect("token should be accepted");
}

#[tokio::test]
async fn verify_token_rejects_missing_when_required() {
    let state = SecurityState::new();
    let policy = SecurityPolicy::default();
    let sessions = SessionManager::new();
    let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
    let parts = make_parts("/sse", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    let now = Instant::now();
    let request = build_request(
        &[],
        &[],
        &sessions,
        true,
        Some(verifier.fingerprint()),
        &parts,
        WebRoute::Sse,
        now,
        None,
    )
    .await
    .unwrap();

    let err = verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
        .await
        .expect_err("missing token should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_token_allows_missing_for_html() {
    let state = SecurityState::new();
    let policy = SecurityPolicy::default();
    let sessions = SessionManager::new();
    let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");
    let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    let now = Instant::now();
    let request = build_request(
        &[],
        &[],
        &sessions,
        true,
        Some(verifier.fingerprint()),
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();

    verify_token(&state, &policy, Some(&verifier), &sessions, &request, now)
        .await
        .expect("html route should allow missing token");
}

#[tokio::test]
async fn verify_token_accepts_session_cookie() {
    let state = SecurityState::new();
    let policy = SecurityPolicy::default();
    let sessions = SessionManager::new();
    let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");

    let token_key = TokenKey::from_value("secret");
    let now = Instant::now();
    let cookie_value = sessions
        .issue(token_key, verifier.fingerprint(), None, now)
        .await;
    let encoded = utf8_percent_encode(&cookie_value, NON_ALPHANUMERIC).to_string();

    let request = Request::builder().uri("/sse").body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    parts.headers.insert(
        COOKIE,
        format!("{SESSION_COOKIE_NAME}={encoded}").parse().unwrap(),
    );
    parts
        .extensions
        .insert(ConnectInfo(std::net::SocketAddr::from((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4242,
        ))));

    let auth_request = build_request(
        &[],
        &[],
        &sessions,
        true,
        Some(verifier.fingerprint()),
        &parts,
        WebRoute::Sse,
        now,
        None,
    )
    .await
    .unwrap();
    verify_token(
        &state,
        &policy,
        Some(&verifier),
        &sessions,
        &auth_request,
        now,
    )
    .await
    .expect("session cookie should be accepted");
}

#[tokio::test]
async fn session_cookie_rejected_on_token_rotation() {
    let sessions = SessionManager::new();
    let verifier_v1 = TokenVerifier::parse(cached_argon2()).expect("parse hash v1");
    let verifier_v2 = TokenVerifier::parse(&argon2_hash("rotated")).expect("parse hash v2");

    let token_key = TokenKey::from_value("secret");
    let now = Instant::now();
    let cookie_value = sessions
        .issue(token_key, verifier_v1.fingerprint(), None, now)
        .await;
    let encoded = utf8_percent_encode(&cookie_value, NON_ALPHANUMERIC).to_string();

    let request = Request::builder().uri("/").body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    parts.headers.insert(
        COOKIE,
        format!("{SESSION_COOKIE_NAME}={encoded}").parse().unwrap(),
    );
    parts
        .extensions
        .insert(ConnectInfo(std::net::SocketAddr::from((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4242,
        ))));

    let auth_request = build_request(
        &[],
        &[],
        &sessions,
        true,
        Some(verifier_v2.fingerprint()),
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();

    assert!(matches!(auth_request.credential, Credential::None));
    assert_eq!(auth_request.token_key, TokenKey::Anonymous);
    assert!(auth_request.purge_session_cookie);
}

#[tokio::test]
async fn session_cookie_is_ignored_when_sessions_disabled() {
    let sessions = SessionManager::new();
    let token_key = TokenKey::from_value("secret");
    let now = Instant::now();
    let cookie_value = sessions.issue(token_key, [0u8; 16], None, now).await;
    let encoded = utf8_percent_encode(&cookie_value, NON_ALPHANUMERIC).to_string();

    let request = Request::builder().uri("/").body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    parts.headers.insert(
        COOKIE,
        format!("{SESSION_COOKIE_NAME}={encoded}").parse().unwrap(),
    );
    parts
        .extensions
        .insert(ConnectInfo(std::net::SocketAddr::from((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4242,
        ))));

    let auth_request = build_request(
        &[],
        &[],
        &sessions,
        false,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();
    assert!(matches!(auth_request.credential, Credential::None));
    assert_eq!(auth_request.token_key, TokenKey::Anonymous);
}

#[tokio::test]
async fn invalid_session_cookie_logs_and_rejects() {
    let state = SecurityState::new();
    let policy = SecurityPolicy::default();
    let sessions = SessionManager::new();
    let verifier = TokenVerifier::parse(cached_argon2()).expect("parse hash");

    let request = Request::builder().uri("/sse").body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    parts.headers.insert(
        COOKIE,
        format!("{SESSION_COOKIE_NAME}=not-a-session")
            .parse()
            .unwrap(),
    );
    parts
        .extensions
        .insert(ConnectInfo(std::net::SocketAddr::from((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4242,
        ))));

    let now = Instant::now();
    let auth_request = build_request(
        &[],
        &[],
        &sessions,
        true,
        Some(verifier.fingerprint()),
        &parts,
        WebRoute::Sse,
        now,
        None,
    )
    .await
    .unwrap();
    let err = verify_token(
        &state,
        &policy,
        Some(&verifier),
        &sessions,
        &auth_request,
        now,
    )
    .await
    .expect_err("invalid session cookie should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn allowlist_rejects_ip_with_forbidden_status() {
    let sessions = SessionManager::new();
    let parts = make_parts("/", IpAddr::V4(Ipv4Addr::LOCALHOST), None);
    let allow = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
    let now = Instant::now();

    let err = build_request(
        &allow,
        &[],
        &sessions,
        false,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .expect_err("unlisted ip should be rejected");
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert!(!err.is_auth_failure());
}

#[tokio::test]
async fn trusted_proxy_overrides_client_ip() {
    let sessions = SessionManager::new();
    let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
    parts.headers.insert(
        "x-forwarded-for",
        "198.51.100.25, 192.0.2.10".parse().unwrap(),
    );
    let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
    let now = Instant::now();
    let request = build_request(
        &[],
        &trusted,
        &sessions,
        true,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        request.remote_ip,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25))
    );
    assert_ne!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
}

#[tokio::test]
async fn trusted_proxy_header_requires_source_hop() {
    let sessions = SessionManager::new();
    let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
    parts
        .headers
        .insert("x-forwarded-for", "198.51.100.25".parse().unwrap());
    let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
    let now = Instant::now();
    let request = build_request(
        &[],
        &trusted,
        &sessions,
        true,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();
    assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
}

#[tokio::test]
async fn trusted_proxy_overrides_client_ip_with_forwarded_header() {
    let sessions = SessionManager::new();
    let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
    parts.headers.insert(
        "forwarded",
        "for=198.51.100.25;proto=https".parse().unwrap(),
    );
    let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
    let now = Instant::now();
    let request = build_request(
        &[],
        &trusted,
        &sessions,
        true,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        request.remote_ip,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25))
    );
}

#[tokio::test]
async fn forwarded_header_mismatched_by_is_ignored() {
    let sessions = SessionManager::new();
    let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), None);
    parts.headers.insert(
        "forwarded",
        "for=198.51.100.25;by=203.0.113.5".parse().unwrap(),
    );
    let trusted = vec![IpMatcher::Exact(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))];
    let now = Instant::now();
    let request = build_request(
        &[],
        &trusted,
        &sessions,
        true,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();
    assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
}

#[tokio::test]
async fn untrusted_proxy_header_is_ignored() {
    let sessions = SessionManager::new();
    let mut parts = make_parts("/", IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), None);
    parts
        .headers
        .insert("x-forwarded-for", "198.51.100.25".parse().unwrap());
    let now = Instant::now();
    let request = build_request(
        &[],
        &[],
        &sessions,
        true,
        None,
        &parts,
        WebRoute::Html,
        now,
        None,
    )
    .await
    .unwrap();
    assert_eq!(request.remote_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
}

#[test]
fn parse_rejects_plaintext() {
    let err = TokenVerifier::parse("not-a-hash").expect_err("plaintext should be rejected");
    assert!(err.contains("non supporté"));
}
