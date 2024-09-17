use crate::domain::exception::auth_domain_exception::AuthDomainException;
use crate::exception::auth_exception::AuthException;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApplicationException {
    #[error(transparent)]
    AuthDomainError(#[from] AuthDomainException),

    #[error(transparent)]
    AuthError(#[from] AuthException),
}
