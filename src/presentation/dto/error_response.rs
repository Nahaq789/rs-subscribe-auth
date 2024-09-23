use http::StatusCode;
use serde::Serialize;

#[derive(Serialize, Debug)]
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

    #[test]
    fn test_error_response_serialize_success() {
        let status_code = StatusCode::OK;
        let message = String::from("hoge");

        let response = ErrorResponse::new(status_code, &message);
        let result = serde_json::to_value(&response).unwrap();

        assert_eq!(result["status_code"], status_code.as_u16());
        assert_eq!(result["message"], message)
    }
}
