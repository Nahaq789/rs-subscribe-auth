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
