use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RefreshState<T> {
    pub data: Option<T>,
    pub last_refresh: Option<Instant>,
    pub last_success: Option<Instant>,
    pub refreshing: bool,
}

impl<T> Default for RefreshState<T> {
    fn default() -> Self {
        Self {
            data: None,
            last_refresh: None,
            last_success: None,
            refreshing: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RefreshUpdate<T> {
    Replace(Option<T>),
    Retain,
}

/// Decide whether a refresh should start based on freshness TTL and cooldown.
pub fn should_start_refresh<T>(
    state: &RefreshState<T>,
    now: Instant,
    success_ttl: Duration,
    failure_retry: Duration,
) -> bool {
    if state.refreshing {
        return false;
    }
    let has_data = state.data.is_some();
    let success_stale = state
        .last_success
        .map(|ts| now.duration_since(ts) > success_ttl)
        .unwrap_or(true);
    let cooldown_active = state
        .last_refresh
        .map(|ts| now.duration_since(ts) < failure_retry)
        .unwrap_or(false);

    if has_data && !success_stale {
        return false;
    }
    if cooldown_active {
        return false;
    }
    true
}

/// Apply refresh completion, updating timestamps and optionally replacing data.
pub fn finish_refresh<T: Clone>(
    state: &mut RefreshState<T>,
    now: Instant,
    update: RefreshUpdate<T>,
) -> Option<T> {
    match update {
        RefreshUpdate::Replace(value) => {
            state.data = value;
            if state.data.is_some() {
                state.last_success = Some(now);
            }
        }
        RefreshUpdate::Retain => {}
    }
    state.last_refresh = Some(now);
    state.refreshing = false;
    state.data.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_start_refresh_respects_ttl_and_cooldown() {
        let now = Instant::now();
        let mut state = RefreshState {
            data: Some(1),
            last_success: Some(now),
            last_refresh: Some(now),
            refreshing: false,
        };

        assert!(
            !should_start_refresh(
                &state,
                now,
                Duration::from_secs(30),
                Duration::from_secs(10)
            ),
            "fresh data should skip refresh"
        );

        // Make it stale but still within cooldown.
        state.last_success = Some(now - Duration::from_secs(40));
        assert!(
            !should_start_refresh(
                &state,
                now,
                Duration::from_secs(30),
                Duration::from_secs(60)
            ),
            "cooldown should block refresh even when stale"
        );

        // Past cooldown.
        state.last_refresh = Some(now - Duration::from_secs(120));
        assert!(
            should_start_refresh(
                &state,
                now,
                Duration::from_secs(30),
                Duration::from_secs(60)
            ),
            "stale outside cooldown should trigger refresh"
        );
    }

    #[test]
    fn finish_refresh_retains_data_when_requested() {
        let now = Instant::now();
        let mut state = RefreshState {
            data: Some(7),
            last_success: Some(now - Duration::from_secs(5)),
            last_refresh: None,
            refreshing: true,
        };

        let cloned = finish_refresh(&mut state, now, RefreshUpdate::Retain);
        assert_eq!(cloned, Some(7));
        assert!(state.last_refresh.is_some());
        assert_eq!(state.last_success, Some(now - Duration::from_secs(5)));
        assert!(!state.refreshing);

        let replaced = finish_refresh(&mut state, now, RefreshUpdate::Replace(Some(9)));
        assert_eq!(replaced, Some(9));
        assert_eq!(state.last_success, Some(now));
    }
}
