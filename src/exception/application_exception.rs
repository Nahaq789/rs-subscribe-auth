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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_exception_auth_domain_error() {
        assert_eq!(
            ApplicationException::AuthDomainError(AuthDomainException::ValidateFailed).to_string(),
            "Validate Error"
        )
    }

    #[test]
    fn test_application_exception_auth_error() {
        assert_eq!(
            ApplicationException::AuthError(AuthException::AuthenticationFailed(
                "hoge".to_string()
            ))
            .to_string(),
            "Authentication failed: hoge"
        )
    }
}
