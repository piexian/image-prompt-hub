//! 进程内限流（governor 令牌桶），按 IP 哈希或密钥 ID 计数。

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::{Clock as _, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use crate::config::RateLimitConfig;
use crate::error::ApiError;

type Keyed = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// 限流器集合；内部 Arc，克隆共享同一份计数。
#[derive(Clone)]
pub struct RateLimiters(Arc<RateLimitersInner>);

pub struct RateLimitersInner {
    anon_read: Keyed,
    keyed_read: Keyed,
    write: Keyed,
    key_request: Keyed,
    key_verify: Keyed,
    report: Keyed,
    auth_attempt: Keyed,
}

impl RateLimiters {
    pub fn new(config: RateLimitConfig) -> Self {
        Self(Self::build(config))
    }

    fn build(config: RateLimitConfig) -> Arc<RateLimitersInner> {
        let per_min = |n: u32| {
            RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(n).expect("限流值已验证为正"),
            ))
        };
        let per_hour = |n: u32| {
            RateLimiter::keyed(Quota::per_hour(
                NonZeroU32::new(n).expect("限流值已验证为正"),
            ))
        };
        Arc::new(RateLimitersInner {
            anon_read: per_min(config.anon_read_per_min),
            keyed_read: per_min(config.keyed_read_per_min),
            write: per_min(config.write_per_min),
            key_request: per_hour(config.key_request_per_hour),
            key_verify: per_hour(config.key_verify_per_hour),
            report: per_hour(config.report_per_hour),
            auth_attempt: per_min(config.auth_attempt_per_min),
        })
    }

    fn all(&self) -> [&Keyed; 7] {
        [
            &self.0.anon_read,
            &self.0.keyed_read,
            &self.0.write,
            &self.0.key_request,
            &self.0.key_verify,
            &self.0.report,
            &self.0.auth_attempt,
        ]
    }

    /// 清理已恢复满额度的键并收缩底层存储，由后台任务定期调用。
    pub fn retain_and_shrink(&self) {
        for limiter in self.all() {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }

    /// 各限流器当前保存状态的键总数，用于观察内存占用。
    pub fn tracked_keys(&self) -> usize {
        self.all().iter().map(|limiter| limiter.len()).sum()
    }

    pub fn check_anon_read(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.anon_read, key)
    }

    pub fn check_keyed_read(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.keyed_read, key)
    }

    pub fn check_write(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.write, key)
    }

    pub fn check_key_request(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.key_request, key)
    }

    pub fn check_key_verify(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.key_verify, key)
    }

    pub fn check_report(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.report, key)
    }

    /// 认证尝试（带 Bearer 的请求在查库之前按客户端 IP 扣减）。
    pub fn check_auth_attempt(&self, key: &str) -> Result<(), ApiError> {
        check(&self.0.auth_attempt, key)
    }
}

fn check(limiter: &Keyed, key: &str) -> Result<(), ApiError> {
    match limiter.check_key(&key.to_string()) {
        Ok(()) => Ok(()),
        Err(denied) => {
            let clock = DefaultClock::default();
            let wait = denied.wait_time_from(clock.now()).as_secs().max(1);
            Err(ApiError::rate_limited(wait))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;

    #[test]
    fn limits_trigger_with_retry_after() {
        let limiters = RateLimiters::new(RateLimitConfig {
            anon_read_per_min: 2,
            ..Default::default()
        });
        assert!(limiters.check_anon_read("ip1").is_ok());
        assert!(limiters.check_anon_read("ip1").is_ok());
        let error = limiters.check_anon_read("ip1").unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::RateLimited);
        assert!(error.retry_after.is_some());
        // 其他键不受影响
        assert!(limiters.check_anon_read("ip2").is_ok());
    }

    #[test]
    fn auth_attempt_is_independent() {
        let limiters = RateLimiters::new(RateLimitConfig {
            auth_attempt_per_min: 2,
            ..Default::default()
        });
        assert!(limiters.check_auth_attempt("ip1").is_ok());
        assert!(limiters.check_auth_attempt("ip1").is_ok());
        assert!(limiters.check_auth_attempt("ip1").is_err());
        // 不影响同 IP 的匿名读
        assert!(limiters.check_anon_read("ip1").is_ok());
    }

    #[test]
    fn retain_and_shrink_drops_only_recovered_keys() {
        // 每分钟 6000 万次即约每微秒恢复一个名额：下面短暂等待后，用过一次的键额度已恢复满
        let limiters = RateLimiters::new(RateLimitConfig {
            anon_read_per_min: 60_000_000,
            // 每小时 1 次：用过之后在测试时长内不会恢复
            key_request_per_hour: 1,
            ..Default::default()
        });
        assert!(limiters.check_anon_read("recovered").is_ok());
        assert!(limiters.check_key_request("exhausted").is_ok());
        assert!(limiters.check_key_request("exhausted").is_err());
        assert_eq!(limiters.tracked_keys(), 2);

        std::thread::sleep(std::time::Duration::from_millis(5));
        limiters.retain_and_shrink();

        assert_eq!(limiters.tracked_keys(), 1, "只应保留仍在限流中的键");
        assert!(
            limiters.check_key_request("exhausted").is_err(),
            "清理不能放走仍在限流的键"
        );
        assert!(limiters.check_anon_read("recovered").is_ok());
    }

    #[test]
    fn write_and_key_request_separate() {
        let limiters = RateLimiters::new(RateLimitConfig {
            write_per_min: 1,
            key_request_per_hour: 1,
            ..Default::default()
        });
        assert!(limiters.check_write("k1").is_ok());
        assert!(limiters.check_write("k1").is_err());
        assert!(limiters.check_key_request("k1").is_ok());
        assert!(limiters.check_key_request("k1").is_err());
    }
}
