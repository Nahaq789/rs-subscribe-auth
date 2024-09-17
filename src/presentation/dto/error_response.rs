use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    status_code: u16,
    message: String,
}

impl ErrorResponse {
    pub fn new(status_code: StatusCode, message: String) -> Self {
        ErrorResponse {
            status_code: status_code.as_u16(),
            message,
        }
    }
}
