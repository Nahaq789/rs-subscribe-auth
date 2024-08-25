use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Internal Server Error")]
    InternalServerError,
}
