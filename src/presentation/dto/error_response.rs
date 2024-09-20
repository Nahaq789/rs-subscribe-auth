use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    status_code: u16,
    message: String,
}

impl ErrorResponse {
    pub fn new(status_code: StatusCode, message: &str) -> Self {
        ErrorResponse {
            status_code: status_code.as_u16(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_create_success() {
        let status_code = StatusCode::BAD_REQUEST;
        let message = String::from("hoge");
        let result = ErrorResponse::new(status_code, &message);

        assert_eq!(result.status_code, StatusCode::BAD_REQUEST);
        assert_eq!(result.message, message)
    }
}
