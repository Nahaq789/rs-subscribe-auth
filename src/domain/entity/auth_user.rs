use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
    pub password: String,
    pub verify_code: String,
}

impl AuthUser {
    pub fn new(user_id: String, email: String, password: String, verify_code: String) -> Self {
        AuthUser {
            user_id,
            email,
            password,
            verify_code,
        }
    }
}
