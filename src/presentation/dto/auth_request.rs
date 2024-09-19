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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use super::*;

    #[test]
    fn test_auth_request_create_success() {
        let email = String::from("hoge@email.com");
        let password = String::from("hogehoge");
        let verify_code = String::from("fugafuga");

        let result = AuthRequest::new(&email, &password, &verify_code);

        assert_eq!(result.email, email);
        assert_eq!(result.password, password);
        assert_eq!(result.verify_code, verify_code)
    }

    #[test]
    fn test_auth_request_deserialize_success() {
        let email = String::from("hoge@email.com");
        let password = String::from("hogehoge");
        let verify_code = String::from("fugafuga");

        let request = json!({
            "email": email,
            "password": password,
            "verify_code": verify_code
        });

        let result = serde_json::from_value::<AuthRequest>(request).unwrap();
        assert_eq!(result.email, email);
        assert_eq!(result.password, password);
        assert_eq!(result.verify_code, verify_code)
    }

    #[test]
    fn test_auth_request_deserialize_failed() {
        let email = String::from("hoge@email.com");
        let password = String::from("hogehoge");
        let verify_code = String::from("fugafuga");

        let request = json!({
            "!email": email,
            "!password": password,
            "!verify_code": verify_code
        });

        let result = serde_json::from_value::<AuthRequest>(request);
        assert!(result.is_err())
    }
}