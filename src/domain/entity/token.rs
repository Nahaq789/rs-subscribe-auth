#[derive(Clone)]
pub struct Token {
    pub jwt: String,
    pub refresh: String,
}

impl Token {
    pub fn new(jwt: String, refresh: String) -> Self {
        Token { jwt, refresh }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::entity::token::Token;

    #[test]
    fn test_token_create_success() {
        let result = Token::new("jwt_token".to_string(), "refresh_token".to_string());

        assert_eq!(result.jwt, "jwt_token".to_string());
        assert_eq!(result.refresh, "refresh_token".to_string())
    }
}
