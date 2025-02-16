use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Session {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl Session {
    pub fn new(user_id: Uuid, expires_at: OffsetDateTime) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            user_id,
            created_at: OffsetDateTime::now_utc(),
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }
}
