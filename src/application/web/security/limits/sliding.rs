use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct SlidingWindowQueue {
    window: Duration,
    hits: VecDeque<Instant>,
}

impl SlidingWindowQueue {
    pub(crate) fn new(window: Duration) -> Self {
        Self {
            window,
            hits: VecDeque::new(),
        }
    }

    pub(crate) fn set_window(&mut self, window: Duration) {
        self.window = window;
    }

    pub(crate) fn purge(&mut self, now: Instant) -> usize {
        let mut removed = 0;
        while let Some(front) = self.hits.front() {
            if now.duration_since(*front) >= self.window {
                self.hits.pop_front();
                removed += 1;
            } else {
                break;
            }
        }
        removed
    }

    #[allow(dead_code)]
    pub(crate) fn register(&mut self, now: Instant) -> usize {
        self.purge(now);
        self.hits.push_back(now);
        self.hits.len()
    }

    pub(crate) fn push(&mut self, now: Instant) -> usize {
        self.hits.push_back(now);
        self.hits.len()
    }

    pub(crate) fn clear(&mut self) {
        self.hits.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.hits.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    pub(crate) fn oldest(&self) -> Option<Instant> {
        self.hits.front().copied()
    }

    #[allow(dead_code)]
    pub(crate) fn newest(&self) -> Option<Instant> {
        self.hits.back().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::SlidingWindowQueue;
    use std::time::{Duration, Instant};

    #[test]
    fn purge_removes_at_window_boundary() {
        let window = Duration::from_secs(10);
        let start = Instant::now();
        let mut queue = SlidingWindowQueue::new(window);

        queue.register(start);
        queue.register(start + Duration::from_secs(5));

        let removed = queue.purge(start + Duration::from_secs(10));
        assert_eq!(removed, 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.oldest(), Some(start + Duration::from_secs(5)));
    }

    #[test]
    fn register_purges_before_push() {
        let window = Duration::from_secs(10);
        let start = Instant::now();
        let mut queue = SlidingWindowQueue::new(window);

        queue.register(start);
        let count = queue.register(start + Duration::from_secs(10));

        assert_eq!(count, 1);
        assert_eq!(queue.oldest(), Some(start + Duration::from_secs(10)));
    }

    #[test]
    fn purge_can_empty_queue() {
        let window = Duration::from_secs(5);
        let start = Instant::now();
        let mut queue = SlidingWindowQueue::new(window);

        queue.register(start);
        queue.purge(start + Duration::from_secs(6));

        assert!(queue.is_empty());
    }
}
