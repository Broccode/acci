use acci_core::clock::Clock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A clock implementation that can be used in tests to control time
#[derive(Clone)]
pub struct TestClock {
    /// The current offset from UNIX_EPOCH in seconds
    offset: Arc<AtomicI64>,
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        let offset = self.offset.load(Ordering::SeqCst);
        UNIX_EPOCH + Duration::from_secs(offset.max(0) as u64)
    }
}

impl TestClock {
    pub fn new() -> Self {
        Self {
            offset: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Advance the clock by the specified duration
    pub fn advance(&self, duration: Duration) {
        self.offset
            .fetch_add(duration.as_secs() as i64, Ordering::SeqCst);
    }

    /// Set the clock to a specific time
    pub fn set(&self, time: SystemTime) {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .expect("Time must be after UNIX_EPOCH");
        self.offset
            .store(duration.as_secs() as i64, Ordering::SeqCst);
    }

    /// Reset the clock to UNIX_EPOCH
    pub fn reset(&self) {
        self.offset.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_clock_operations() {
        let clock = TestClock::new();
        assert_eq!(clock.now(), UNIX_EPOCH);

        // Test advance
        clock.advance(Duration::from_secs(60));
        assert_eq!(
            clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            60
        );

        // Test set
        let new_time = UNIX_EPOCH + Duration::from_secs(3600);
        clock.set(new_time);
        assert_eq!(clock.now(), new_time);

        // Test reset
        clock.reset();
        assert_eq!(clock.now(), UNIX_EPOCH);
    }

    #[test]
    fn test_clock_thread_safety() {
        let clock = TestClock::new();
        let clock2 = clock.clone();

        let handle = thread::spawn(move || {
            clock2.advance(Duration::from_secs(60));
        });

        clock.advance(Duration::from_secs(30));
        handle.join().unwrap();

        assert_eq!(
            clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            90
        );
    }

    #[test]
    fn test_clock_trait_implementation() {
        let clock = TestClock::new();
        let now = clock.now();
        assert_eq!(now, UNIX_EPOCH);

        // Test that Clock trait methods work with time advancement
        clock.advance(Duration::from_secs(120));
        let advanced = clock.now();
        assert_eq!(advanced.duration_since(UNIX_EPOCH).unwrap().as_secs(), 120);
    }
}
