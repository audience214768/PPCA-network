use std::sync::Mutex;
use std::time::Instant;

pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,  // tokens / second
    burst: f64, // max capacity
}

impl TokenBucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
            rate,
            burst,
        }
    }
    pub fn try_consume(limiter: &Mutex<Self>) -> bool { //true for allowed
        let mut b = limiter.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(b.last_refill).as_secs_f64();
        b.tokens = (b.tokens + elapsed * b.rate).min(b.burst);
        b.last_refill = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
