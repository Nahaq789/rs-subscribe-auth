use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct AuthResult {
    jwt: String,
    refresh: String,
    status_code: i32,
}

impl AuthResult {
    pub fn new(jwt: &str, refresh: &str, status_code: i32) -> Self {
        AuthResult {
            jwt: jwt.into(),
            refresh: refresh.into(),
            status_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result_create_success() {
        let jwt = String::from("hogehoge");
        let refresh = String::from("fugafuga");
        let status_code = 200;

        let result = AuthResult::new(&jwt, &refresh, status_code);
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.refresh, refresh);
        assert_eq!(result.status_code, status_code)
    }

    #[test]
    fn test_auth_result_serialize_success() {
        let jwt = String::from("hogehoge");
        let refresh = String::from("fugafuga");
        let status_code = 200;

        let response = AuthResult::new(&jwt, &refresh, status_code);

        let result = serde_json::to_value(&response).unwrap();

        assert_eq!(result["jwt"], jwt);
        assert_eq!(result["refresh"], refresh);
        assert_eq!(result["status_code"], status_code)
    }
}
