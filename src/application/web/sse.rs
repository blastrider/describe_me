use std::{
    borrow::Cow,
    convert::Infallible,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    response::IntoResponse,
};
use futures_util::{stream::StreamExt, Stream};
use pin_project::{pin_project, pinned_drop};
use tokio::sync::Notify;
use tokio::time::{self, MissedTickBehavior};
use tokio_stream::wrappers::IntervalStream;

use crate::application::capture_snapshot_with_view;
use crate::application::logging::LogEvent;
use crate::domain::CaptureOptions;

use super::security::{AuthGuard, GlobalPermit, SsePermit, TokenKey};
use super::{mark_response_no_store, set_session_cookie, AppState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SseCloseReason {
    Natural,
    Limit,
    Error,
}

impl SseCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            SseCloseReason::Natural => "natural",
            SseCloseReason::Limit => "limit",
            SseCloseReason::Error => "error",
        }
    }
}

struct StreamPayload {
    event: Event,
    close_after: Option<SseCloseReason>,
    bytes: usize,
}

struct SseMetrics {
    start: Instant,
    max_duration: Duration,
    max_bytes: usize,
    ip: IpAddr,
    token: TokenKey,
    events: AtomicU64,
    bytes: AtomicU64,
    reason: AtomicU8,
}

impl SseMetrics {
    fn new(ip: IpAddr, token: TokenKey, max_duration: Duration, max_bytes: usize) -> Self {
        Self {
            start: Instant::now(),
            max_duration,
            max_bytes,
            ip,
            token,
            events: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            reason: AtomicU8::new(SseCloseReason::Natural as u8),
        }
    }

    fn record_event(&self, payload_bytes: usize) -> bool {
        self.events.fetch_add(1, Ordering::Relaxed);
        if self.max_bytes > 0 {
            let total = self
                .bytes
                .fetch_add(payload_bytes as u64, Ordering::Relaxed)
                + payload_bytes as u64;
            if total > self.max_bytes as u64 {
                self.set_reason(SseCloseReason::Limit);
                return true;
            }
        }
        false
    }

    fn set_reason(&self, reason: SseCloseReason) {
        let _ = self.reason.compare_exchange(
            SseCloseReason::Natural as u8,
            reason as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    fn limit_exceeded(&self) -> bool {
        if self.max_duration.is_zero() {
            return false;
        }
        if self.start.elapsed() >= self.max_duration {
            self.set_reason(SseCloseReason::Limit);
            return true;
        }
        false
    }

    fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn duration_seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    fn reason(&self) -> SseCloseReason {
        match self.reason.load(Ordering::Relaxed) {
            x if x == SseCloseReason::Limit as u8 => SseCloseReason::Limit,
            x if x == SseCloseReason::Error as u8 => SseCloseReason::Error,
            _ => SseCloseReason::Natural,
        }
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }

    fn token(&self) -> TokenKey {
        self.token
    }
}

#[pin_project(PinnedDrop)]
struct MetricsStream<S> {
    #[pin]
    inner: S,
    metrics: Arc<SseMetrics>,
    pending_close: Option<SseCloseReason>,
    permit: Option<SsePermit>,
    global_permit: Option<GlobalPermit>,
    #[pin]
    shutdown_fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    shutdown_triggered: bool,
}

impl<S> MetricsStream<S> {
    fn new(
        inner: S,
        metrics: Arc<SseMetrics>,
        permit: Option<SsePermit>,
        global_permit: Option<GlobalPermit>,
        shutdown: Arc<Notify>,
    ) -> Self {
        let shutdown_clone = shutdown.clone();
        let shutdown_fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>> =
            Box::pin(async move {
                shutdown_clone.notified().await;
            });
        Self {
            inner,
            metrics,
            pending_close: None,
            permit,
            global_permit,
            shutdown_fut,
            shutdown_triggered: false,
        }
    }
}

impl<S> Stream for MetricsStream<S>
where
    S: Stream<Item = Result<StreamPayload, Infallible>>,
{
    type Item = Result<Event, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if !*this.shutdown_triggered {
            if this.shutdown_fut.as_mut().poll(cx).is_ready() {
                *this.shutdown_triggered = true;
                this.metrics.set_reason(SseCloseReason::Limit);
                return Poll::Ready(None);
            }
        } else {
            return Poll::Ready(None);
        }

        if let Some(reason) = this.pending_close.take() {
            this.metrics.set_reason(reason);
            return Poll::Ready(None);
        }

        if this.metrics.limit_exceeded() {
            return Poll::Ready(None);
        }

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(payload))) => {
                let StreamPayload {
                    event,
                    close_after,
                    bytes,
                } = payload;
                let exceeded = this.metrics.record_event(bytes);
                if let Some(reason) = close_after {
                    this.metrics.set_reason(reason);
                    *this.pending_close = Some(reason);
                } else if exceeded {
                    *this.pending_close = Some(SseCloseReason::Limit);
                }
                Poll::Ready(Some(Ok(event)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[pinned_drop]
impl<S> PinnedDrop for MetricsStream<S> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        let metrics = this.metrics;
        let reason = metrics.reason();
        LogEvent::SseStreamClosed {
            ip: Cow::Owned(metrics.ip().to_string()),
            token: Cow::Owned(metrics.token().to_string()),
            events: metrics.events(),
            duration_s: metrics.duration_seconds(),
            reason: Cow::Borrowed(reason.as_str()),
            bytes: metrics.bytes(),
        }
        .emit();
    }
}

pub(super) async fn sse_stream(
    State(state): State<AppState>,
    guard: AuthGuard,
) -> impl IntoResponse {
    #[cfg(feature = "systemd")]
    let with_services = true;
    #[cfg(not(feature = "systemd"))]
    let with_services = false;

    let mut session = guard.into_session();
    let cookie_token = session.session_cookie().map(str::to_owned);
    let client_ip = session.ip();
    let token_key = session.token_key();
    let permit = session.take_sse_permit();
    let global_permit = session.take_global_permit();
    let policy = state.security.policy();
    let shutdown_notify = state.shutdown.clone();

    let mut interval = state.interval;
    let min_interval = policy.sse_min_event_interval();
    if interval < min_interval {
        interval = min_interval;
    }

    let max_payload = policy.sse_max_payload_bytes();
    let max_duration = policy.sse_max_stream_duration();
    let min_interval_ms = min_interval.as_millis().min(u128::from(u64::MAX)) as u64;
    let max_stream_s = max_duration.as_secs();

    let max_stream_bytes = policy.sse_max_stream_bytes();
    let metrics = Arc::new(SseMetrics::new(
        client_ip,
        token_key,
        max_duration,
        max_stream_bytes,
    ));
    let metrics_for_stream = metrics.clone();

    LogEvent::SseStreamOpen {
        ip: Cow::Owned(client_ip.to_string()),
        token: Cow::Owned(token_key.to_string()),
        min_interval_ms,
        max_payload,
        max_stream_s,
        max_stream_bytes,
    }
    .emit();

    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    #[cfg(feature = "config")]
    let config = state.config.clone();
    let exposure = state.exposure;
    let updates_cache = state.updates_cache.clone();

    let stream = IntervalStream::new(ticker).then(move |_| {
        #[cfg(feature = "config")]
        let config = config.clone();
        let exposure = exposure;
        let max_payload = max_payload;
        let metrics = metrics_for_stream.clone();
        let updates_cache = updates_cache.clone();

        async move {
            if exposure.updates() {
                updates_cache.ensure_fresh().await;
            }

            let (payload, services_count, partitions_count, close_after) =
                match capture_snapshot_with_view(
                    CaptureOptions {
                        with_services,
                        with_disk_usage: true,
                        with_listening_sockets: exposure.listening_sockets(),
                        resolve_socket_processes: false,
                        with_network_traffic: exposure.network_traffic(),
                        with_updates: false,
                    },
                    exposure,
                    #[cfg(feature = "config")]
                    config.as_ref(),
                ) {
                    Ok((_snapshot, mut view)) => {
                        if exposure.updates() {
                            if let Some(info) = updates_cache.peek().await {
                                view.updates = Some(info);
                            }
                        }
                        #[cfg(feature = "systemd")]
                        let services_count = view
                            .services_running
                            .as_ref()
                            .map(|services| services.len());
                        #[cfg(not(feature = "systemd"))]
                        let services_count = None::<usize>;
                        let partitions_count = view
                            .disk_usage
                            .as_ref()
                            .and_then(|du| du.partitions.as_ref().map(|p| p.len()));
                        (
                            serde_json::to_string(&view)
                                .unwrap_or_else(|e| json_err(e.to_string())),
                            services_count,
                            partitions_count,
                            None,
                        )
                    }
                    Err(e) => (
                        json_err(e.to_string()),
                        None,
                        None,
                        Some(SseCloseReason::Error),
                    ),
                };
            let payload_len = payload.len();

            LogEvent::SseTick {
                payload_bytes: payload_len,
                services_count,
                partitions: partitions_count,
            }
            .emit();

            let event = if payload_len > max_payload {
                LogEvent::SsePayloadOversize {
                    size: payload_len,
                    limit: max_payload,
                }
                .emit();
                Event::default().data(json_err("payload SSE trop volumineux"))
            } else {
                Event::default().data(payload)
            };

            if let Some(reason) = close_after {
                metrics.set_reason(reason);
            }

            Ok::<StreamPayload, Infallible>(StreamPayload {
                event,
                close_after,
                bytes: payload_len,
            })
        }
    });

    let stream = MetricsStream::new(stream, metrics, permit, global_permit, shutdown_notify);

    let sse = Sse::new(stream).keep_alive(KeepAlive::default());
    let mut response = sse.into_response();
    mark_response_no_store(response.headers_mut());
    if let Some(token) = cookie_token.as_deref() {
        set_session_cookie(response.headers_mut(), token, state.session_cookie_secure);
    }
    response
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn json_err(msg: impl AsRef<str>) -> String {
    format!(r#"{{"error":"{}"}}"#, escape_json(msg.as_ref()))
}
