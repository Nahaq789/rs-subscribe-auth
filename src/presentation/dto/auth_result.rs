use serde::Serialize;

#[derive(Serialize)]
pub struct AuthResult {
    jwt: String,
    refresh: String,
    status_code: i32,
}

impl AuthResult {
    pub fn new(jwt: &String, refresh: &String, status_code: i32) -> Self {
        AuthResult {
            jwt: jwt.to_string(),
            refresh: refresh.to_string(),
            status_code,
        }
    }
}
