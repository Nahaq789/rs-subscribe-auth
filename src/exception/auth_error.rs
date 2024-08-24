use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid email or password: {0}")]
    InvalidCredentials(String),
}
