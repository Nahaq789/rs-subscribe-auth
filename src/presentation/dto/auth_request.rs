use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
    pub verify_code: String,
}

impl AuthRequest {
    pub fn new(email: &String, password: &String, verify_code: &String) -> Self {
        AuthRequest {
            email: email.to_string(),
            password: password.to_string(),
            verify_code: verify_code.to_string(),
        }
    }
}
