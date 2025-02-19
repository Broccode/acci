use crate::mocks::{MockSessionRepository, MockUserRepository};
use acci_auth::AuthService;
use acci_core::{
    auth::{AuthConfig, Credentials},
    error::Error,
    models::User,
};
use acci_db::models::Session;
use mockall::predicate::eq;
use proptest::prelude::*;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use time::OffsetDateTime;
use tokio::time::sleep;
use uuid::Uuid;

#[derive(Debug, Clone)]
enum RateLimitStrategy {
    /// Fixed window rate limiting
    /// Resets counter at fixed intervals
    FixedWindow { limit: u32, window: Duration },

    /// Sliding window rate limiting
    /// Uses a moving time window
    SlidingWindow {
        limit: u32,
        window: Duration,
        precision: Duration,
    },

    /// Token bucket rate limiting
    /// Allows bursts while maintaining average rate
    TokenBucket {
        rate: f64,
        capacity: u32,
        initial_tokens: u32,
    },

    /// Leaky bucket rate limiting
    /// Processes requests at a constant rate
    LeakyBucket { rate: f64, capacity: u32 },
}

impl RateLimitStrategy {
    fn is_allowed(&self, history: &[SystemTime]) -> bool {
        match self {
            RateLimitStrategy::FixedWindow { limit, window } => {
                let now = SystemTime::now();
                let window_start = now - *window;
                let requests_in_window =
                    history.iter().filter(|&time| *time >= window_start).count();
                requests_in_window < *limit as usize
            },
            RateLimitStrategy::SlidingWindow {
                limit,
                window,
                precision,
            } => {
                let now = SystemTime::now();
                let window_start = now - *window;

                // Count requests in each precision bucket
                let bucket_count = (window.as_secs_f64() / precision.as_secs_f64()).ceil() as usize;
                let mut buckets = vec![0; bucket_count];

                for time in history {
                    if *time >= window_start {
                        let elapsed = time
                            .duration_since(window_start)
                            .unwrap_or(Duration::from_secs(0));
                        let bucket = (elapsed.as_secs_f64() / precision.as_secs_f64()) as usize;
                        if bucket < bucket_count {
                            buckets[bucket] += 1;
                        }
                    }
                }

                let total_requests: u32 = buckets.iter().sum();
                total_requests < *limit
            },
            RateLimitStrategy::TokenBucket {
                rate,
                capacity,
                initial_tokens,
            } => {
                if history.is_empty() {
                    return true; // First request always allowed
                }

                let now = SystemTime::now();
                let first_request = history.first().unwrap();
                let elapsed = now
                    .duration_since(*first_request)
                    .unwrap_or(Duration::from_secs(0));

                // Calculate available tokens
                let generated_tokens = (elapsed.as_secs_f64() * rate) as u32;
                let total_tokens = (*initial_tokens + generated_tokens).min(*capacity);
                let used_tokens = history.len() as u32;

                total_tokens > used_tokens
            },
            RateLimitStrategy::LeakyBucket { rate, capacity } => {
                if history.is_empty() {
                    return true; // First request always allowed
                }

                let now = SystemTime::now();
                let mut queue_size = 0;

                // Calculate current queue size
                for time in history.iter().rev() {
                    let elapsed = now.duration_since(*time).unwrap_or(Duration::from_secs(0));
                    let processed = (elapsed.as_secs_f64() * rate) as u32;
                    if processed < 1 {
                        queue_size += 1;
                    }
                }

                queue_size < *capacity
            },
        }
    }
}

#[tokio::test]
async fn test_rate_limiting_basic() -> Result<(), Error> {
    let mut user_repo = MockUserRepository::new();
    let mut session_repo = MockSessionRepository::new();
    let now = OffsetDateTime::now_utc();
    let user_id = Uuid::new_v4();

    // Setup test user
    let test_user = User {
        id: user_id,
        username: "test.user@example.com".to_string(),
        email: "test.user@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        is_admin: false,
        created_at: now,
        updated_at: now,
    };

    user_repo
        .expect_get_user_by_username()
        .with(eq(&test_user.username))
        .returning(move |_| Ok(Some(test_user.clone())))
        .times(6); // Allow 5 attempts + 1 successful

    let session_id = Uuid::new_v4();
    let token = "test_token".to_string();
    let expires_at = now + time::Duration::hours(24);

    session_repo
        .expect_create_session()
        .with(eq(user_id), eq(token.as_str()), eq(expires_at))
        .returning(move |user_id, token, expires_at| {
            Ok(Session {
                id: session_id,
                user_id,
                token: token.to_string(),
                created_at: now,
                expires_at,
            })
        });

    let auth_service = AuthService::new(Arc::new(user_repo), Arc::new(session_repo));

    let credentials = Credentials {
        username: test_user.username.clone(),
        password: "wrong_password".to_string(),
    };

    // Attempt rapid authentication
    for _ in 0..5 {
        let result = auth_service.authenticate(&credentials).await;
        assert!(result.is_err());
        sleep(Duration::from_millis(100)).await;
    }

    // Wait for rate limit to reset
    sleep(Duration::from_secs(30)).await;

    // Try again with correct password
    let credentials = Credentials {
        username: test_user.username,
        password: "correct_password".to_string(),
    };

    let result = auth_service.authenticate(&credentials).await;
    assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_fixed_window_rate_limiting() {
    let strategy = RateLimitStrategy::FixedWindow {
        limit: 5,
        window: Duration::from_secs(1),
    };

    let mut history = Vec::new();

    // Test initial requests within limit
    for _ in 0..5 {
        assert!(
            strategy.is_allowed(&history),
            "Should allow requests within limit"
        );
        history.push(SystemTime::now());
        sleep(Duration::from_millis(100)).await;
    }

    // Test request exceeding limit
    assert!(
        !strategy.is_allowed(&history),
        "Should deny requests exceeding limit"
    );

    // Test after window expiration
    sleep(Duration::from_secs(1)).await;
    assert!(
        strategy.is_allowed(&history),
        "Should allow requests after window reset"
    );
}

#[tokio::test]
async fn test_sliding_window_rate_limiting() {
    let strategy = RateLimitStrategy::SlidingWindow {
        limit: 5,
        window: Duration::from_secs(1),
        precision: Duration::from_millis(100),
    };

    let mut history = Vec::new();

    // Test initial requests within limit
    for _ in 0..5 {
        assert!(
            strategy.is_allowed(&history),
            "Should allow requests within limit"
        );
        history.push(SystemTime::now());
        sleep(Duration::from_millis(100)).await;
    }

    // Test request exceeding limit
    assert!(
        !strategy.is_allowed(&history),
        "Should deny requests exceeding limit"
    );

    // Test sliding behavior
    sleep(Duration::from_millis(600)).await;
    assert!(
        strategy.is_allowed(&history),
        "Should allow requests as window slides"
    );
}

#[tokio::test]
async fn test_token_bucket_rate_limiting() {
    let strategy = RateLimitStrategy::TokenBucket {
        rate: 5.0,
        capacity: 10,
        initial_tokens: 5,
    };

    let mut history = Vec::new();

    // Test burst capability
    for _ in 0..5 {
        assert!(strategy.is_allowed(&history), "Should allow initial burst");
        history.push(SystemTime::now());
    }

    // Test rate limiting
    assert!(
        !strategy.is_allowed(&history),
        "Should deny requests when tokens depleted"
    );

    // Test token regeneration
    sleep(Duration::from_secs(1)).await;
    assert!(
        strategy.is_allowed(&history),
        "Should allow requests after token regeneration"
    );
}

#[tokio::test]
async fn test_leaky_bucket_rate_limiting() {
    let strategy = RateLimitStrategy::LeakyBucket {
        rate: 5.0,
        capacity: 5,
    };

    let mut history = Vec::new();

    // Test initial capacity
    for _ in 0..5 {
        assert!(
            strategy.is_allowed(&history),
            "Should allow requests within capacity"
        );
        history.push(SystemTime::now());
    }

    // Test capacity limit
    assert!(
        !strategy.is_allowed(&history),
        "Should deny requests exceeding capacity"
    );

    // Test leaking behavior
    sleep(Duration::from_secs(1)).await;
    assert!(
        strategy.is_allowed(&history),
        "Should allow requests after leaking"
    );
}

proptest! {
    #[test]
    fn test_fixed_window_properties(
        limit in 1u32..100,
        window_secs in 1u64..60,
        request_count in 1usize..200
    ) {
        let strategy = RateLimitStrategy::FixedWindow {
            limit,
            window: Duration::from_secs(window_secs),
        };

        let mut history = Vec::new();
        for _ in 0..request_count {
            if history.len() < limit as usize {
                prop_assert!(strategy.is_allowed(&history));
            }
            history.push(SystemTime::now());
        }

        // Property: Never allow more than limit requests in window
        let requests_in_window = history.iter()
            .filter(|&time| time.elapsed().unwrap() <= Duration::from_secs(window_secs))
            .count();
        prop_assert!(requests_in_window <= limit as usize);
    }

    #[test]
    fn test_sliding_window_properties(
        limit in 1u32..100,
        window_secs in 1u64..60,
        precision_millis in 100u64..1000,
        request_count in 1usize..200
    ) {
        let strategy = RateLimitStrategy::SlidingWindow {
            limit,
            window: Duration::from_secs(window_secs),
            precision: Duration::from_millis(precision_millis),
        };

        let mut history = Vec::new();
        for _ in 0..request_count {
            if strategy.is_allowed(&history) {
                history.push(SystemTime::now());
            }
        }

        // Property: Never allow more than limit requests in any sliding window
        let now = SystemTime::now();
        let window_start = now - Duration::from_secs(window_secs);
        let requests_in_window = history.iter()
            .filter(|&time| *time >= window_start)
            .count();
        prop_assert!(requests_in_window <= limit as usize);
    }

    #[test]
    fn test_token_bucket_properties(
        rate in 1.0..100.0,
        capacity in 1u32..100,
        initial_tokens in 0u32..50,
        request_count in 1usize..200
    ) {
        let strategy = RateLimitStrategy::TokenBucket {
            rate,
            capacity,
            initial_tokens,
        };

        let mut history = Vec::new();
        for _ in 0..request_count {
            if strategy.is_allowed(&history) {
                history.push(SystemTime::now());
            }
        }

        // Property: Never exceed capacity
        prop_assert!(history.len() <= capacity as usize);

        // Property: Initial burst respects initial tokens
        let initial_requests = history.iter()
            .take_while(|&time| time.elapsed().unwrap() <= Duration::from_secs(1))
            .count();
        prop_assert!(initial_requests <= initial_tokens as usize);
    }

    #[test]
    fn test_leaky_bucket_properties(
        rate in 1.0..100.0,
        capacity in 1u32..100,
        request_count in 1usize..200
    ) {
        let strategy = RateLimitStrategy::LeakyBucket {
            rate,
            capacity,
        };

        let mut history = Vec::new();
        for _ in 0..request_count {
            if strategy.is_allowed(&history) {
                history.push(SystemTime::now());
            }
        }

        // Property: Never exceed capacity
        prop_assert!(history.len() <= capacity as usize);

        // Property: Maintain constant rate
        if history.len() >= 2 {
            let first = history.first().unwrap();
            let last = history.last().unwrap();
            let elapsed = last.duration_since(*first).unwrap();
            let actual_rate = history.len() as f64 / elapsed.as_secs_f64();
            prop_assert!(actual_rate <= rate * 1.1); // Allow 10% margin
        }
    }
}
