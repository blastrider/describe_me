mod claim;
mod cookie;
mod manager;
mod store;

pub(crate) use claim::ClientClaim;
pub use cookie::{clear_session_cookie, set_session_cookie, SESSION_COOKIE_NAME};
pub(super) use manager::{SessionCandidate, SessionError};
pub(crate) use manager::{SessionManager, WebSession};

pub(super) const SESSION_COOKIE_PREFIX: &str = "sess:v1:";
