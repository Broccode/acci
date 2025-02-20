use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{error, info};

use acci_db::repositories::session::SessionRepository;

/// Runs the session cleanup task periodically.
///
/// This task runs in the background and removes expired sessions from the database.
/// The cleanup interval is configurable through the `cleanup_interval` parameter.
///
/// # Arguments
///
/// * `session_repo` - The session repository implementation
/// * `cleanup_interval` - The interval between cleanup runs in seconds
pub async fn run_session_cleanup(
    session_repo: Arc<dyn SessionRepository + Send + Sync>,
    cleanup_interval: u64,
) {
    info!(
        "Starting session cleanup task with interval: {}s",
        cleanup_interval
    );
    let mut interval = time::interval(Duration::from_secs(cleanup_interval));

    loop {
        interval.tick().await;
        match session_repo.cleanup_expired_sessions().await {
            Ok(count) => {
                if count > 0 {
                    info!("Cleaned up {} expired sessions", count);
                }
            },
            Err(e) => {
                error!("Failed to cleanup expired sessions: {}", e);
            },
        }
    }
}
