use thiserror::Error;

/// Represents various authentication-related errors that can occur in the application.
///
/// This enum covers a range of error scenarios related to user authentication,
/// including issues with the authentication process itself, server-side problems,
/// configuration errors, and user input validation failures.
#[derive(Error, Debug)]
pub enum AuthException {
    /// Indicates that the authentication process has failed.
    ///
    /// This error is typically raised when the provided credentials (username/email and password)
    /// do not match any existing user account, or when there's an issue with the authentication
    /// service (e.g., AWS Cognito) that prevents successful authentication.
    ///
    /// # Examples
    ///
    /// - Incorrect password provided for an existing username
    /// - Non-existent username/email used for login attempt
    /// - Authentication service temporary failure
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Represents an internal server error with additional context.
    ///
    /// This error is used for unexpected issues that occur on the server side during
    /// the authentication process. It includes a string parameter to provide more
    /// detailed information about the nature of the error.
    ///
    /// # Examples
    ///
    /// - Database connection failures
    /// - Unexpected exceptions in the authentication logic
    /// - Integration errors with external services
    #[error("Internal Server Error: {0}")]
    InternalServerError(String),

    /// Indicates an error in the configuration of the authentication system.
    ///
    /// This error is raised when there are issues with the setup or configuration
    /// of the authentication service or related components.
    ///
    /// # Examples
    ///
    /// - Missing or invalid AWS credentials
    /// - Incorrectly configured Cognito User Pool
    /// - Missing required environment variables
    #[error("Configuration Error")]
    ConfigurationError,

    /// Signifies that an expected authentication token is missing.
    ///
    /// This error occurs when the authentication process does not return the
    /// expected tokens (e.g., access token, refresh token) upon successful login.
    ///
    /// # Examples
    ///
    /// - Access token missing in Cognito response
    /// - Refresh token not provided after successful authentication
    #[error("Token Missing")]
    TokenMissing,

    /// Indicates that an attempt was made to register a user with an email that already exists.
    ///
    /// This error is raised during the user registration process when the provided
    /// email address is already associated with an existing account.
    ///
    /// # Examples
    ///
    /// - Attempting to sign up with an email that's already registered
    /// - Duplicate user creation attempt
    #[error("User already exists: An account with this email address is already registered")]
    UserAlreadyExists,

    /// Signifies that the provided password does not meet the required criteria.
    ///
    /// This error is raised during user registration or password change operations
    /// when the supplied password does not conform to the defined password policy.
    ///
    /// # Examples
    ///
    /// - Password is too short
    /// - Password lacks required character types (e.g., uppercase, numbers, symbols)
    /// - Password matches common patterns or known weak passwords
    #[error("Invalid password: Password does not meet the required criteria")]
    InvalidPassword,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_exception_authentication_failed() {
        assert_eq!(
            AuthException::AuthenticationFailed("hoge".to_string()).to_string(),
            "Authentication failed: hoge"
        )
    }

    #[test]
    fn test_auth_exception_internal_server_error() {
        assert_eq!(
            AuthException::InternalServerError("hoge".to_string()).to_string(),
            "Internal Server Error: hoge"
        )
    }

    #[test]
    fn test_auth_exception_configuration_error() {
        assert_eq!(
            AuthException::ConfigurationError.to_string(),
            "Configuration Error"
        )
    }

    #[test]
    fn test_auth_exception_token_missing() {
        assert_eq!(AuthException::TokenMissing.to_string(), "Token Missing")
    }

    #[test]
    fn test_auth_exception_user_already_exists() {
        assert_eq!(
            AuthException::UserAlreadyExists.to_string(),
            "User already exists: An account with this email address is already registered"
        )
    }

    #[test]
    fn test_auth_exception_invalid_password() {
        assert_eq!(
            AuthException::InvalidPassword.to_string(),
            "Invalid password: Password does not meet the required criteria"
        )
    }
}
