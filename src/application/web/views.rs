//! View models used by HTML rendering.
//!
//! The goal is to keep handlers focused on data retrieval while letting
//! `template.rs` assemble the HTML. Each new page should introduce a simple
//! view model that lists the data needed by the template (strings, options,
//! booleans, etc.) and pass it to a dedicated `render_*` function in
//! `template.rs`.

use crate::domain::UpdatesInfo;

/// Data required to render the index page.
#[derive(Debug, Clone)]
pub(super) struct IndexViewModel<'a> {
    pub web_debug: bool,
    pub csp_nonce: &'a str,
}

/// Data required to render the updates page.
#[derive(Debug, Clone)]
pub(super) struct UpdatesViewModel<'a> {
    pub updates: Option<&'a UpdatesInfo>,
    pub message: Option<&'a str>,
    pub csp_nonce: &'a str,
}

/// Data required to render the logs page.
#[derive(Debug, Clone)]
pub(super) struct LogsViewModel<'a> {
    pub csp_nonce: &'a str,
}

/// Data required to render the containers page.
#[derive(Debug, Clone)]
pub(super) struct ContainersViewModel<'a> {
    pub csp_nonce: &'a str,
}
