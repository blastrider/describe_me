use std::sync::atomic::{AtomicU32, Ordering};

use super::super::WebRoute;

#[derive(Debug, Default)]
pub(crate) struct GlobalSlots {
    active: AtomicU32,
}

impl GlobalSlots {
    pub(crate) fn new() -> Self {
        Self {
            active: AtomicU32::new(0),
        }
    }

    pub(crate) fn try_acquire(&self, limit: u32) -> Result<(), ()> {
        if limit == 0 {
            return Ok(());
        }
        let mut current = self.active.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return Err(());
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn release(&self) {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
                if value == 0 {
                    Some(0)
                } else {
                    Some(value - 1)
                }
            })
            .ok();
    }
}

#[derive(Debug, Default)]
pub(crate) struct GlobalSlotsByRoute {
    html: GlobalSlots,
    sse: GlobalSlots,
    history: GlobalSlots,
    logs: GlobalSlots,
    metrics: GlobalSlots,
}

impl GlobalSlotsByRoute {
    pub(crate) fn new() -> Self {
        Self {
            html: GlobalSlots::new(),
            sse: GlobalSlots::new(),
            history: GlobalSlots::new(),
            logs: GlobalSlots::new(),
            metrics: GlobalSlots::new(),
        }
    }

    pub(crate) fn for_route(&self, route: WebRoute) -> &GlobalSlots {
        match route {
            WebRoute::Html => &self.html,
            WebRoute::Sse => &self.sse,
            WebRoute::History => &self.history,
            WebRoute::Logs => &self.logs,
            WebRoute::Metrics => &self.metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_slots_is_concurrency_not_window() {
        let slots = GlobalSlots::new();
        assert!(slots.try_acquire(1).is_ok());
        assert!(slots.try_acquire(1).is_err());
        slots.release();
        assert!(slots.try_acquire(1).is_ok());
    }

    #[test]
    fn global_slots_by_route_is_isolated() {
        let slots = GlobalSlotsByRoute::new();
        let html = slots.for_route(WebRoute::Html);
        let sse = slots.for_route(WebRoute::Sse);

        assert!(html.try_acquire(1).is_ok());
        assert!(html.try_acquire(1).is_err());
        assert!(sse.try_acquire(1).is_ok());
    }
}
