//! RTT statistics: min, avg, max, stddev, and packet loss.

pub struct RttStats {
    pub sent: u32,
    pub received: u32,
    pub rtt_min: f64,
    pub rtt_max: f64,
    pub rtt_sum: f64,
    pub rtt_sum_sq: f64,
}

impl RttStats {
    pub fn new() -> Self {
        Self {
            sent: 0,
            received: 0,
            rtt_min: f64::MAX,
            rtt_max: 0.0,
            rtt_sum: 0.0,
            rtt_sum_sq: 0.0,
        }
    }

    pub fn record(&mut self, rtt_ms: f64) {
        self.received += 1;
        self.rtt_min = self.rtt_min.min(rtt_ms);
        self.rtt_max = self.rtt_max.max(rtt_ms);
        self.rtt_sum += rtt_ms;
        self.rtt_sum_sq += rtt_ms * rtt_ms;
    }

    pub fn avg(&self) -> f64 {
        if self.received == 0 {
            return 0.0;
        }
        self.rtt_sum / self.received as f64
    }

    pub fn stddev(&self) -> f64 {
        if self.received == 0 {
            return 0.0;
        }
        let mean = self.avg();
        let mean_sq = self.rtt_sum_sq / self.received as f64;
        let variance = mean_sq - mean * mean;
        if variance < 0.0 {
            0.0
        } else {
            variance.sqrt()
        }
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        let lost = self.sent.saturating_sub(self.received);
        (lost as f64 / self.sent as f64) * 100.0
    }

    pub fn print_summary(&self, host: &str, resolved: &str) {
        println!("\n--- {host} ({resolved}) ping statistics ---");
        println!(
            "{} packets transmitted, {} packets received, {:.1}% packet loss",
            self.sent,
            self.received,
            self.loss_pct()
        );
        if self.received > 0 {
            println!(
                "round-trip min/avg/max/stddev = {:.3}/{:.3}/{:.3}/{:.3} ms",
                self.rtt_min,
                self.avg(),
                self.rtt_max,
                self.stddev()
            );
        }
    }
}
