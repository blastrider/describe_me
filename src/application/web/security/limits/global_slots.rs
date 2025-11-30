use std::sync::atomic::{AtomicU32, Ordering};

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
