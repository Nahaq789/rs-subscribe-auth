use password_hash::PasswordHasher;
use pbkdf2::{
    password_hash::{rand_core::OsRng, SaltString},
    Params, Pbkdf2,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthUser {
    pub name: String,
    pub password: String,
}

impl AuthUser {
    fn hash_password(&self, password: &[u8], salt: &String) -> Result<String, password_hash::Error> {
        let salt_string = SaltString::from_b64(&salt)?;
                let params: Params = pbkdf2::Params {
            rounds: (10000),
            output_length: (32),
        };

        let hash = Pbkdf2
            .hash_password_customized(password, None, None, params, &salt_string)
            .map(|hash| hash.to_string())
            .unwrap_or_else(|_| "Error: Failed to hash password".to_string());

        Ok(hash)
    }
}