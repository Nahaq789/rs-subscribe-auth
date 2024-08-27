use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
}

impl AuthRequest {
    pub fn new(email: &String, password: &String) -> Self {
        AuthRequest {
            email: email.to_string(),
            password: password.to_string(),
        }
    }
}
