//! 进程内限流（governor 令牌桶），按 IP 哈希或密钥 ID 计数。

use std::num::NonZeroU32;
use std::sync::Arc;

use std::collections::HashMap;
use std::time::{Duration, Instant};

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
    auth_failure: AuthFailureWindow,
}

/// 认证失败的固定窗口计数器：只在认证失败后计数，成功不消耗任何额度。
/// 窗口内失败次数达到上限后，该 IP 的所有带 Bearer 请求（包括有效密钥）
/// 在查库之前就被拒绝——这是为了挡住无效密钥洪泛，正常使用不会触发。
pub struct AuthFailureWindow {
    limit: u32,
    window: Duration,
    failures: std::sync::Mutex<HashMap<String, (Instant, u32)>>,
}

impl AuthFailureWindow {
    pub fn new(limit: u32) -> Self {
        Self {
            limit: limit.max(1),
            window: Duration::from_secs(60),
            failures: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 只读检查：达到上限时返回应等待的秒数（窗口剩余时间）。
    /// 带时间参数的版本供单元测试构造时间点，不依赖真实时钟。
    pub fn check_at(&self, key: &str, now: Instant) -> Option<u64> {
        let map = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match map.get(key) {
            Some((start, count)) if now.duration_since(*start) < self.window => (*count
                >= self.limit)
                .then(|| (self.window - now.duration_since(*start)).as_secs().max(1)),
            _ => None,
        }
    }

    /// 记录一次认证失败，返回当前窗口内的失败总数。
    pub fn record_failure_at(&self, key: &str, now: Instant) -> u32 {
        let mut map = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match map.get_mut(key) {
            Some((start, count)) if now.duration_since(*start) < self.window => {
                *count += 1;
                *count
            }
            _ => {
                map.insert(key.to_string(), (now, 1));
                1
            }
        }
    }

    /// 清理过期的窗口记录，并入定期清理任务。
    pub fn prune_at(&self, now: Instant) {
        let mut map = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.retain(|_, (start, _)| now.duration_since(*start) < self.window);
    }

    fn check(&self, key: &str) -> Option<u64> {
        self.check_at(key, Instant::now())
    }

    fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now());
    }
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
            auth_failure: AuthFailureWindow::new(config.auth_failure_per_min),
        })
    }

    fn all(&self) -> [&Keyed; 6] {
        [
            &self.0.anon_read,
            &self.0.keyed_read,
            &self.0.write,
            &self.0.key_request,
            &self.0.key_verify,
            &self.0.report,
        ]
    }

    /// 清理已恢复满额度的键并收缩底层存储，由后台任务定期调用。
    pub fn retain_and_shrink(&self) {
        self.0.auth_failure.prune_at(Instant::now());
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

    /// 查库前只读检查认证失败窗口：达到上限直接 429。
    pub fn check_auth_failure(&self, key: &str) -> Result<(), ApiError> {
        match self.0.auth_failure.check(key) {
            Some(retry_after) => Err(ApiError::rate_limited(retry_after)),
            None => Ok(()),
        }
    }

    /// 认证失败（401）后计数。
    pub fn record_auth_failure(&self, key: &str) {
        self.0.auth_failure.record_failure(key);
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
    fn auth_failure_window_only_counts_failures() {
        let window = AuthFailureWindow::new(3);
        let t0 = Instant::now();
        // 没有失败时无论检查多少次都不会拦截（成功请求不消耗额度）
        for _ in 0..100 {
            assert_eq!(window.check_at("ip1", t0), None);
        }
        // 失败 1、2 次仍放行，第 3 次达到上限
        assert_eq!(window.record_failure_at("ip1", t0), 1);
        assert_eq!(window.record_failure_at("ip1", t0), 2);
        assert_eq!(window.check_at("ip1", t0), None);
        assert_eq!(window.record_failure_at("ip1", t0), 3);
        let retry = window.check_at("ip1", t0).expect("达到上限应拦截");
        assert!(retry <= 60, "重试等待不超过窗口长度：{retry}");
        // 窗口推进，剩余等待时间单调不增
        let later = window
            .check_at("ip1", t0 + Duration::from_secs(30))
            .unwrap();
        assert!(later <= retry);
        // 窗口过期后恢复，且重新计数
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(window.check_at("ip1", t1), None);
        assert_eq!(window.record_failure_at("ip1", t1), 1);
    }

    #[test]
    fn auth_failure_keys_are_independent() {
        let window = AuthFailureWindow::new(1);
        let t0 = Instant::now();
        assert_eq!(window.record_failure_at("ip1", t0), 1);
        assert!(window.check_at("ip1", t0).is_some());
        assert_eq!(window.check_at("ip2", t0), None, "不同 IP 互不影响");
    }

    #[test]
    fn auth_failure_prune_removes_expired_keys() {
        let window = AuthFailureWindow::new(1);
        let t0 = Instant::now();
        window.record_failure_at("old", t0);
        window.record_failure_at("fresh", t0 + Duration::from_secs(30));
        window.prune_at(t0 + Duration::from_secs(61));
        let map = window
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!map.contains_key("old"), "过期键应被清理");
        assert!(map.contains_key("fresh"), "窗口内的键保留");
    }

    #[test]
    fn auth_failure_via_rate_limiters_returns_429() {
        let limiters = RateLimiters::new(RateLimitConfig {
            auth_failure_per_min: 1,
            ..Default::default()
        });
        assert!(limiters.check_auth_failure("ip1").is_ok());
        limiters.record_auth_failure("ip1");
        let error = limiters.check_auth_failure("ip1").unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::RateLimited);
        assert!(error.retry_after.is_some());
        // 不影响同 IP 的匿名读（认证窗口独立于读限流）
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
