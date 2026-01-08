use super::{
    auth::AuthRequest,
    limits::{SecurityPolicy, SecurityState, SsePolicy},
    SecurityRejection, TokenKey, WebRoute,
};
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::warn;

pub(super) async fn acquire_permit(
    state: &SecurityState,
    policy: &SecurityPolicy,
    request: &AuthRequest,
) -> Result<Option<SsePermit>, SecurityRejection> {
    if request.route != WebRoute::Sse {
        return Ok(None);
    }

    match state
        .acquire_sse(request.remote_ip, request.token_key, policy)
        .await
    {
        Ok(permit) => Ok(permit),
        Err(delay) => {
            let delay = policy.adjust_retry(request.route, delay);
            warn!(
                ip = %request.remote_ip,
                route = request.route.as_str(),
                token = %request.token_key,
                retry_after = %delay.as_secs_f32(),
                "Limite de connexions SSE atteinte"
            );
            Err(SecurityRejection::rate_limited(delay))
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct ActiveSse {
    per_ip: HashMap<IpAddr, u32>,
    per_token: HashMap<TokenKey, u32>,
}

#[derive(Debug)]
pub(super) struct ActiveSseState {
    inner: Mutex<ActiveSse>,
}

impl ActiveSseState {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ActiveSse::default()),
        })
    }

    pub(super) async fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        token: TokenKey,
        limits: &SsePolicy,
    ) -> Result<Option<SsePermit>, Duration> {
        if limits.max_active_per_ip() == 0 && limits.max_active_per_token() == 0 {
            return Ok(None);
        }

        let mut inner = self.inner.lock().await;
        let apply_token_limit = limits.max_active_per_token() > 0 && token != TokenKey::Anonymous;

        if limits.max_active_per_ip() > 0 {
            let current = inner.per_ip.get(&ip).copied().unwrap_or(0);
            if current >= limits.max_active_per_ip() {
                return Err(Duration::from_secs(0));
            }
        }

        if apply_token_limit {
            let current = inner.per_token.get(&token).copied().unwrap_or(0);
            if current >= limits.max_active_per_token() {
                return Err(Duration::from_secs(0));
            }
        }

        let mut track_ip = false;
        if limits.max_active_per_ip() > 0 {
            let entry = inner.per_ip.entry(ip).or_insert(0);
            *entry += 1;
            track_ip = true;
        }

        let mut track_token = false;
        if apply_token_limit {
            let entry = inner.per_token.entry(token).or_insert(0);
            *entry += 1;
            track_token = true;
        }

        Ok(Some(SsePermit {
            state: Arc::clone(self),
            ip,
            token,
            track_ip,
            track_token,
        }))
    }

    pub(super) async fn release(
        &self,
        ip: IpAddr,
        token: TokenKey,
        track_ip: bool,
        track_token: bool,
    ) {
        let mut inner = self.inner.lock().await;
        Self::release_inner(&mut inner, ip, token, track_ip, track_token);
    }

    pub(super) fn try_release(
        &self,
        ip: IpAddr,
        token: TokenKey,
        track_ip: bool,
        track_token: bool,
    ) -> bool {
        match self.inner.try_lock() {
            Ok(mut inner) => {
                Self::release_inner(&mut inner, ip, token, track_ip, track_token);
                true
            }
            Err(_) => false,
        }
    }

    pub(super) fn release_blocking(
        &self,
        ip: IpAddr,
        token: TokenKey,
        track_ip: bool,
        track_token: bool,
    ) {
        let mut inner = self.inner.blocking_lock();
        Self::release_inner(&mut inner, ip, token, track_ip, track_token);
    }

    fn release_inner(
        inner: &mut ActiveSse,
        ip: IpAddr,
        token: TokenKey,
        track_ip: bool,
        track_token: bool,
    ) {
        if track_ip {
            if let Some(count) = inner.per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    inner.per_ip.remove(&ip);
                }
            }
        }
        if track_token {
            if let Some(count) = inner.per_token.get_mut(&token) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    inner.per_token.remove(&token);
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct SsePermit {
    state: Arc<ActiveSseState>,
    ip: IpAddr,
    token: TokenKey,
    track_ip: bool,
    track_token: bool,
}

impl Drop for SsePermit {
    fn drop(&mut self) {
        let state = Arc::clone(&self.state);
        let ip = self.ip;
        let token = self.token;
        let track_ip = self.track_ip;
        let track_token = self.track_token;
        if state.try_release(ip, token, track_ip, track_token) {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                state.release(ip, token, track_ip, track_token).await;
            });
        } else {
            state.release_blocking(ip, token, track_ip, track_token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::web::security::auth::Credential;
    use axum::http::StatusCode;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn request(ip: IpAddr, token: TokenKey) -> AuthRequest {
        AuthRequest {
            route: WebRoute::Sse,
            request_path: Arc::from("/sse"),
            remote_ip: ip,
            credential: Credential::None,
            token_key: token,
            require_token: true,
            trusted_ip: false,
            purge_session_cookie: false,
            client_claim: None,
        }
    }

    #[tokio::test]
    async fn acquire_permit_honours_limits() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let req = request(IpAddr::V4(Ipv4Addr::LOCALHOST), TokenKey::Anonymous);

        let _first = acquire_permit(&state, &policy, &req)
            .await
            .expect("first permit ok")
            .expect("permit expected");
        let err = acquire_permit(&state, &policy, &req)
            .await
            .expect_err("second permit should fail");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn anonymous_tokens_do_not_share_per_token_limit() {
        let state = SecurityState::new();
        let policy = SecurityPolicy::default();
        let req_local = request(IpAddr::V4(Ipv4Addr::LOCALHOST), TokenKey::Anonymous);
        let req_other = request(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            TokenKey::Anonymous,
        );

        let _first = acquire_permit(&state, &policy, &req_local)
            .await
            .expect("first permit ok")
            .expect("permit expected");
        let _second = acquire_permit(&state, &policy, &req_other)
            .await
            .expect("second permit ok")
            .expect("permit expected");
    }
}
