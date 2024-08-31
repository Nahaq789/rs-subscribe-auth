use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Internal Server Error: {0}")]
    InternalServerError(String),

    #[error("Configuration Error")]
    ConfigurationError,

    #[error("Token Missing")]
    TokenMissing,

    #[error("User already exists: An account with this email address is already registered")]
    UserAlreadyExists,

    #[error("Invalid password: Password does not meet the required criteria")]
    InvalidPassword,
}
