use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Bucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate_per_sec: u32) -> Self {
        let cap = rate_per_sec as f64;
        Self {
            tokens: cap,
            capacity: cap,
            rate: cap,
            last: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Server-wide token-bucket rate limiter.  Clone is cheap (Arc).
#[derive(Clone)]
pub struct RateLimiter(Arc<Mutex<Bucket>>);

impl RateLimiter {
    pub fn new(rate_per_sec: u32) -> Self {
        Self(Arc::new(Mutex::new(Bucket::new(rate_per_sec))))
    }

    /// Returns `true` if the caller may proceed, `false` if the bucket is empty.
    pub fn try_consume(&self) -> bool {
        self.0.lock().unwrap().try_consume()
    }
}
