//! Shared blocking HTTP retry/backoff for `pwninit`-managed requests.
//!
//! This module is the single source of truth for retry policy, backoff
//! sequencing, retryable HTTP status classification, retryable request and
//! body-error classification, and blocking HTTP helpers. Both the Launchpad
//! JSON lookup path and the Ubuntu `.deb` package download path are expected
//! to route their blocking HTTP operations through this module so that the
//! retry behavior, log messages, and error categories stay consistent.
//!
//! Design goals:
//!
//! * Retry policy is finite and bounded. Callers observe a non-zero backoff
//!   between retryable attempts so retries cannot degenerate into zero-delay
//!   hot loops.
//! * Transient request failures, body read failures, HTTP `408`, HTTP `429`,
//!   and HTTP `5xx` are retried.
//! * HTTP `4xx` other than `408` and `429`, malformed JSON, and other
//!   decoding failures are permanent and never retried.
//! * Tests do not actually sleep. They inject a [`Sleeper`] implementation
//!   that records the requested delays.
//!
//! This module is internal. It does not change CLI arguments or surface any
//! user-facing flags.

#![allow(dead_code)]

use std::borrow::Cow;
use std::thread;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::Method;
use serde::de::DeserializeOwned;
use snafu::Snafu;

/// Return `true` for HTTP statuses that are safe to retry: `408`,
/// `429`, and any `5xx`.
///
/// All other `4xx` codes are permanent and must not be retried.
pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

/// Return `true` for [`reqwest::Error`] values that should be retried.
///
/// We retry timeouts, connection failures, general request failures (DNS,
/// TLS, etc.), and body read failures. Decode failures (e.g. malformed
/// JSON) are permanent and never retried.
pub fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request() || err.is_body()
}

/// Final error returned to callers after the retry loop has stopped.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("HTTP request failed: {}", source))]
    Request { source: reqwest::Error },

    #[snafu(display("HTTP request returned permanent status: {}", status))]
    PermanentStatus { status: reqwest::StatusCode },

    #[snafu(display("HTTP request returned retryable status: {}", status))]
    RetryableStatus { status: reqwest::StatusCode },

    #[snafu(display("failed to parse response body: {}", message))]
    Parse { message: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Bounded retry policy with non-zero exponential backoff.
///
/// The policy controls:
///
/// * [`RetryPolicy::max_attempts`] - total attempts, including the first
///   one. Must be at least one.
/// * [`RetryPolicy::initial_backoff`] - backoff before the first retry.
/// * [`RetryPolicy::max_backoff`] - upper bound for any backoff delay.
///
/// Backoff is exponential (`initial_backoff * 2^attempt`), capped at
/// `max_backoff`. The returned backoff is always strictly greater than
/// zero so the retry loop cannot degenerate into a hot spin.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 6,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(10),
        }
    }
}

impl RetryPolicy {
    /// Backoff duration before retrying after `attempt` 0-based failures.
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        // `checked_shl` guards against undefined behavior on extreme shifts.
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        let dur = self.initial_backoff.saturating_mul(factor);
        let bounded = if dur > self.max_backoff {
            self.max_backoff
        } else {
            dur
        };
        if bounded.is_zero() {
            // Guarantee a strictly positive backoff so the retry loop never
            // busy-spins on misconfigured policies.
            Duration::from_millis(1)
        } else {
            bounded
        }
    }
}

/// Abstraction over sleeping so tests do not actually wait.
///
/// Production code uses [`StdSleeper`]. Tests inject a recorder that
/// captures scheduled delays without blocking.
pub trait Sleeper {
    fn sleep(&mut self, dur: Duration);
}

/// Production [`Sleeper`] that actually blocks the current thread.
#[derive(Default)]
pub struct StdSleeper;

impl Sleeper for StdSleeper {
    fn sleep(&mut self, dur: Duration) {
        thread::sleep(dur);
    }
}

/// Recorded retry activity for a single call.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RetryTrace {
    /// Total number of attempts performed (including the final one).
    pub attempts: u32,
    /// Backoff durations scheduled between attempts. The length is
    /// `attempts - 1` when retries were needed and `0` otherwise.
    pub backoffs: Vec<Duration>,
}

/// Outcome of a single attempt of a retried operation.
pub enum RetryOutcome<T> {
    /// The attempt produced a successful value.
    Success(T),
    /// The attempt failed with an error that is safe to retry.
    Transient(Error),
    /// The attempt failed with an error that must not be retried.
    Permanent(Error),
}

/// Drive an operation through a [`RetryPolicy`].
///
/// The operation is invoked up to `policy.max_attempts` times. Between
/// retryable attempts the configured backoff is requested from `sleeper`,
/// the durations are appended to [`RetryTrace::backoffs`], and the loop
/// keeps going until the operation succeeds or exhausts the budget.
///
/// A [`RetryOutcome::Permanent`] short-circuits the loop and is returned
/// as-is to the caller. A [`RetryOutcome::Transient`] that exceeds the
/// configured attempt budget is also returned to the caller, preserving
/// the final transient error.
pub fn retry_with_policy<T, F>(
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
    mut op: F,
) -> Result<(T, RetryTrace)>
where
    F: FnMut() -> RetryOutcome<T>,
{
    let mut trace = RetryTrace::default();
    loop {
        trace.attempts += 1;
        match op() {
            RetryOutcome::Success(value) => return Ok((value, trace)),
            RetryOutcome::Permanent(err) => return Err(err),
            RetryOutcome::Transient(err) => {
                if trace.attempts >= policy.max_attempts {
                    return Err(err);
                }
                let delay = policy.backoff_for(trace.attempts - 1);
                trace.backoffs.push(delay);
                sleeper.sleep(delay);
            }
        }
    }
}

fn transfer_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .user_agent(concat!("pwninit/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|source| Error::Request { source })
}

fn request_bytes(
    method: Method,
    url: &str,
    body: Option<Cow<'_, [u8]>>,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<(Vec<u8>, RetryTrace)> {
    let client = transfer_client()?;
    retry_with_policy(policy, sleeper, || -> RetryOutcome<Vec<u8>> {
        let mut req = client.request(method.clone(), url);
        if let Some(body) = body.as_ref() {
            req = req.body(body.clone().into_owned());
        }

        let resp = match req.send() {
            Ok(resp) => resp,
            Err(source) => {
                return if is_retryable_error(&source) {
                    RetryOutcome::Transient(Error::Request { source })
                } else {
                    RetryOutcome::Permanent(Error::Request { source })
                };
            }
        };

        let status = resp.status();
        if status.is_success() {
            match resp.bytes() {
                Ok(bytes) => RetryOutcome::Success(bytes.to_vec()),
                // `resp.bytes()` in reqwest 0.13.2 wraps every error as
                // `Kind::Decode` (via `crate::error::decode`), including
                // body read failures like truncated bodies and connection
                // drops. All such errors are body read errors, so we
                // retry them as transient failures.
                Err(source) => RetryOutcome::Transient(Error::Request { source }),
            }
        } else if is_retryable_status(status) {
            RetryOutcome::Transient(Error::RetryableStatus { status })
        } else {
            RetryOutcome::Permanent(Error::PermanentStatus { status })
        }
    })
}

/// Fetch `url` and return the full response body as bytes, retrying
/// transient failures.
pub fn get_bytes(
    url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<(Vec<u8>, RetryTrace)> {
    request_bytes(Method::GET, url, None, policy, sleeper)
}

/// Upload `body` to `url` with POST and return the full response body as
/// bytes, retrying transient failures.
pub fn post_bytes(
    url: &str,
    body: &[u8],
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<(Vec<u8>, RetryTrace)> {
    request_bytes(Method::POST, url, Some(Cow::Borrowed(body)), policy, sleeper)
}

/// Fetch `url` and decode the response body as JSON into `T`, retrying
/// transient failures.
///
/// The response body is read into memory first so that body read failures
/// (such as a truncated response) are classified as transient and retried.
/// JSON parse failures on a complete body are permanent and are never
/// retried.
pub fn get_json<T>(
    url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<(T, RetryTrace)>
where
    T: DeserializeOwned,
{
    let client = transfer_client()?;
    retry_with_policy(policy, sleeper, || -> RetryOutcome<T> {
        let resp = match client.get(url).send() {
            Ok(resp) => resp,
            Err(source) => {
                return if is_retryable_error(&source) {
                    RetryOutcome::Transient(Error::Request { source })
                } else {
                    RetryOutcome::Permanent(Error::Request { source })
                };
            }
        };

        let status = resp.status();
        if status.is_success() {
            // Read the full body first so a truncated body (which reqwest
            // classifies as `Decode` from the `bytes()` call) is a
            // transient retryable error, distinct from a complete body
            // that fails to parse as JSON.
            let bytes = match resp.bytes() {
                Ok(bytes) => bytes,
                // `resp.bytes()` in reqwest 0.13.2 wraps every error as
                // `Kind::Decode` (via `crate::error::decode`), including
                // body read failures like truncated bodies and connection
                // drops. All such errors are body read errors, so we
                // retry them as transient failures.
                Err(source) => return RetryOutcome::Transient(Error::Request { source }),
            };
            match serde_json::from_slice::<T>(&bytes) {
                Ok(value) => RetryOutcome::Success(value),
                Err(source) => RetryOutcome::Permanent(Error::Parse {
                    message: source.to_string(),
                }),
            }
        } else if is_retryable_status(status) {
            RetryOutcome::Transient(Error::RetryableStatus { status })
        } else {
            RetryOutcome::Permanent(Error::PermanentStatus { status })
        }
    })
    .map(|(value, trace)| (value, trace))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Sleeper` that records scheduled delays without actually waiting.
    #[derive(Default)]
    struct RecordingSleeper {
        sleeps: Vec<Duration>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&mut self, dur: Duration) {
            self.sleeps.push(dur);
        }
    }

    fn test_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(40),
        }
    }

    fn transient() -> Error {
        Error::RetryableStatus {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn permanent() -> Error {
        Error::PermanentStatus {
            status: reqwest::StatusCode::NOT_FOUND,
        }
    }

    #[test]
    fn default_policy_is_finite_and_uses_nonzero_backoff() {
        let p = RetryPolicy::default();
        assert!(p.max_attempts >= 2, "must allow at least one retry");
        assert!(p.max_attempts <= 10, "must stay bounded");
        assert!(p.initial_backoff > Duration::ZERO);
        assert!(p.max_backoff >= p.initial_backoff);
        assert!(p.backoff_for(0) > Duration::ZERO);
    }

    #[test]
    fn backoff_grows_and_caps_at_max_backoff() {
        let p = test_policy();
        let first = p.backoff_for(0);
        let second = p.backoff_for(1);
        let third = p.backoff_for(2);
        let fourth = p.backoff_for(3);

        assert!(first > Duration::ZERO);
        assert!(second >= first, "backoff should be non-decreasing");
        assert!(third >= second);
        assert!(fourth >= third);
        assert!(fourth <= p.max_backoff, "backoff must respect the cap");
    }

    #[test]
    fn backoff_falls_back_to_one_millisecond_when_initial_is_zero() {
        let p = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        };
        assert_eq!(p.backoff_for(0), Duration::from_millis(1));
        assert_eq!(p.backoff_for(1), Duration::from_millis(1));
    }

    #[test]
    fn backoff_handles_extreme_attempt_counts_without_panic() {
        let p = RetryPolicy::default();
        // Attempt values that would overflow `1u32 << attempt`.
        for attempt in [0u32, 31, 32, 64, u32::MAX] {
            let dur = p.backoff_for(attempt);
            assert!(dur > Duration::ZERO);
            assert!(dur <= p.max_backoff);
        }
    }

    #[test]
    fn classifies_408_429_and_5xx_as_retryable() {
        assert!(is_retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        for code in [
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::BAD_GATEWAY,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            reqwest::StatusCode::GATEWAY_TIMEOUT,
            reqwest::StatusCode::HTTP_VERSION_NOT_SUPPORTED,
        ] {
            assert!(
                is_retryable_status(code),
                "status {} should be retryable",
                code
            );
        }
    }

    #[test]
    fn classifies_other_4xx_as_permanent() {
        for code in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::CONFLICT,
            reqwest::StatusCode::GONE,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert!(
                !is_retryable_status(code),
                "status {} should not be retryable",
                code
            );
        }
        // 1xx, 2xx, 3xx are neither retryable nor permanent in the helper's
        // sense, but they are also not retried because we treat them as
        // permanent (i.e. handled by the caller's own logic).
        assert!(!is_retryable_status(reqwest::StatusCode::OK));
        assert!(!is_retryable_status(reqwest::StatusCode::MOVED_PERMANENTLY));
    }

    #[test]
    fn retry_succeeds_after_transient_failures() {
        let mut sleeper = RecordingSleeper::default();
        let mut attempts: u32 = 0;
        let (value, trace): (i32, RetryTrace) = retry_with_policy(
            test_policy(),
            &mut sleeper,
            || {
                attempts += 1;
                if attempts < 3 {
                    RetryOutcome::Transient(transient())
                } else {
                    RetryOutcome::Success(42)
                }
            },
        )
        .expect("retry should succeed");

        assert_eq!(value, 42);
        assert_eq!(trace.attempts, 3);
        assert_eq!(trace.backoffs.len(), 2);
        assert_eq!(sleeper.sleeps.len(), 2);
        assert!(sleeper.sleeps.iter().all(|d| *d > Duration::ZERO));
    }

    #[test]
    fn retry_stops_at_max_attempts_and_returns_final_transient_error() {
        let mut sleeper = RecordingSleeper::default();
        let mut attempts: u32 = 0;
        let err = retry_with_policy::<i32, _>(test_policy(), &mut sleeper, || {
            attempts += 1;
            RetryOutcome::Transient(Error::RetryableStatus {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            })
        })
        .expect_err("retry must fail when attempts are exhausted");

        assert_eq!(attempts, test_policy().max_attempts);
        assert_eq!(
            sleeper.sleeps.len() as u32,
            test_policy().max_attempts - 1
        );
        match err {
            Error::RetryableStatus { status } => {
                assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR)
            }
            other => panic!("expected RetryableStatus error, got {:?}", other),
        }
    }

    #[test]
    fn retry_does_not_retry_permanent_outcomes() {
        let mut sleeper = RecordingSleeper::default();
        let mut attempts: u32 = 0;
        let err = retry_with_policy::<i32, _>(test_policy(), &mut sleeper, || {
            attempts += 1;
            RetryOutcome::Permanent(permanent())
        })
        .expect_err("permanent outcome should fail immediately");

        assert_eq!(attempts, 1);
        assert!(sleeper.sleeps.is_empty());
        match err {
            Error::PermanentStatus { status } => {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND)
            }
            other => panic!("expected PermanentStatus error, got {:?}", other),
        }
    }

    #[test]
    fn first_attempt_success_does_not_sleep() {
        let mut sleeper = RecordingSleeper::default();
        let (value, trace): (i32, RetryTrace) = retry_with_policy(
            test_policy(),
            &mut sleeper,
            || RetryOutcome::Success(7),
        )
        .expect("first-attempt success");

        assert_eq!(value, 7);
        assert_eq!(trace.attempts, 1);
        assert!(trace.backoffs.is_empty());
        assert!(sleeper.sleeps.is_empty());
    }

    #[test]
    fn retry_trace_records_each_backoff_in_order() {
        let mut sleeper = RecordingSleeper::default();
        let policy = RetryPolicy {
            max_attempts: 4,
            initial_backoff: Duration::from_millis(8),
            max_backoff: Duration::from_millis(64),
        };

        let mut attempts: u32 = 0;
        let (_value, trace): (i32, RetryTrace) = retry_with_policy(policy, &mut sleeper, || {
            attempts += 1;
            if attempts < 4 {
                RetryOutcome::Transient(transient())
            } else {
                RetryOutcome::Success(attempts as i32)
            }
        })
        .expect("retry should succeed");

        assert_eq!(trace.attempts, 4);
        assert_eq!(trace.backoffs.len(), 3);
        assert_eq!(trace.backoffs[0], policy.backoff_for(0));
        assert_eq!(trace.backoffs[1], policy.backoff_for(1));
        assert_eq!(trace.backoffs[2], policy.backoff_for(2));
        assert_eq!(sleeper.sleeps, trace.backoffs);
    }

    #[test]
    fn recording_sleeper_does_not_block() {
        // Sanity check: instantiating a recording sleeper and asking it to
        // sleep for a large duration must not block. If this ever does, the
        // abstraction regressed to actually sleeping.
        let mut sleeper = RecordingSleeper::default();
        sleeper.sleep(Duration::from_secs(3600));
        assert_eq!(sleeper.sleeps, vec![Duration::from_secs(3600)]);
    }
}
