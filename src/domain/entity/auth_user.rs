use anyhow::Result;
use password_hash::{Error as PasswordHashError, PasswordHasher};
use pbkdf2::{password_hash::SaltString, Params, Pbkdf2};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthUser {
    pub name: String,
    pub password: String,
}

impl AuthUser {
    pub fn new(name: String, password: &str, salt: &String) -> Result<Self, PasswordHashError> {
        let salt = SaltString::from_b64(&salt)?;
        let hashed_password = Self::hash_password(password.as_bytes(), &salt)?;

        Ok(Self {
            name,
            password: hashed_password,
        })
    }
    fn hash_password(password: &[u8], salt: &SaltString) -> Result<String, PasswordHashError> {
        let params: Params = pbkdf2::Params {
            rounds: (10000),
            output_length: (32),
        };

        Pbkdf2
            .hash_password_customized(password, None, None, params, salt)
            .map(|hash| hash.to_string())
    }
}
