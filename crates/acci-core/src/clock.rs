use std::time::SystemTime;

/// A trait for providing the current time.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current time.
    fn now(&self) -> SystemTime;
}

/// Implementation of Clock trait using `SystemTime` for production.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_system_clock() {
        let clock = SystemClock::default();
        let now = clock.now();
        let system_now = SystemTime::now();

        // The difference between the two times should be very small (less than 1ms)
        let diff = system_now
            .duration_since(now)
            .unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_millis(1));
    }
}
