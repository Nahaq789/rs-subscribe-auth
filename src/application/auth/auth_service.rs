use std::sync::Arc;

use axum::async_trait;


use crate::{
    domain::{
        entity::{auth_user::AuthUser, token::Token},
        repository::cognito_repository::CognitoRepository,
    },
    exception::auth_error::AuthError,
    presentation::dto::auth_request::AuthRequest,
};

/// Defines the core authentication operations for the application.
///
/// This trait encapsulates the essential authentication functionalities,
/// including user authentication, signup, and a combined signup-signin process.
/// Implementations of this trait should handle the intricacies of interacting
/// with the chosen authentication backend (e.g., AWS Cognito) while providing
/// a clean, abstracted interface for the rest of the application to use.
///
/// The trait is designed to be asynchronous and thread-safe, allowing for
/// efficient handling of authentication requests in a concurrent environment.
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Authenticates a user with the provided credentials.
    ///
    /// This method attempts to authenticate a user against the backend authentication
    /// service. If successful, it returns a `Token` containing the necessary
    /// authentication information (e.g., JWT, refresh token).
    ///
    /// # Arguments
    ///
    /// * `auth` - An `AuthRequest` containing the user's credentials.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(Token)` containing the authentication tokens if successful.
    /// - `Err(AuthError)` if authentication fails for any reason.
    async fn authenticate_user(&self, auth: AuthRequest) -> Result<Token, AuthError>;

    /// Registers a new user with the authentication service.
    ///
    /// This method attempts to create a new user account in the backend authentication
    /// service using the provided user information.
    ///
    /// # Arguments
    ///
    /// * `auth` - An `AuthRequest` containing the new user's information.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(SignUpOutput)` containing the signup result if successful.
    /// - `Err(AuthError)` if signup fails for any reason (e.g., user already exists).
    async fn signup_user(&self, auth: AuthRequest) -> Result<(), AuthError>;

    /// Confirms a user's signup using a verification code.
    ///
    /// This method is typically used to complete the registration process by verifying
    /// the user's email or phone number.
    ///
    /// # Arguments
    ///
    /// * `auth` - An `AuthRequest` containing the user's information and verification code.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(ConfirmSignUpOutput)` if the confirmation is successful.
    /// - `Err(AuthError)` if the confirmation fails for any reason.
    async fn confirm_code(&self, auth: AuthRequest) -> Result<(), AuthError>;
}

/// Implements the AuthService trait using AWS Cognito as the authentication backend.
///
/// This struct provides concrete implementations for user authentication, signup,
/// and combined signup-signin processes using AWS Cognito. It encapsulates the
/// complexity of interacting with Cognito, including the generation of secret hashes
/// and handling of Cognito-specific errors.
#[derive(Clone)]
pub struct AuthServiceImpl<T: CognitoRepository> {
    /// The Cognito repository instance used for interacting with AWS Cognito.
    cognito_repository: Arc<T>,
}

impl<T: CognitoRepository> AuthServiceImpl<T> {
    /// Creates a new instance of AuthServiceImpl.
    ///
    /// # Arguments
    ///
    /// * `cognito_repository` - An instance of a type implementing the CognitoRepository trait,
    ///                          providing access to AWS Cognito configuration and client.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `AuthServiceImpl`.
    pub fn new(cognito_repository: Arc<T>) -> Self {
        AuthServiceImpl { cognito_repository }
    }
}

#[async_trait]
impl<T: CognitoRepository> AuthService for AuthServiceImpl<T> {
    /// Authenticates a user using AWS Cognito.
    ///
    /// This method translates the `AuthRequest` into an `AuthUser` and delegates
    /// the authentication process to the Cognito repository.
    ///
    /// # Arguments
    ///
    /// * `auth` - An `AuthRequest` containing the user's credentials.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a `Token` on success, or an `AuthError` on failure.
    async fn authenticate_user(&self, auth: AuthRequest) -> Result<Token, AuthError> {
        let user = AuthUser::new("".to_string(), auth.email, auth.password, "".to_string());
        let result = self.cognito_repository.authenticate_user(&user).await?;
        Ok(result)
    }

    /// Signs up a new user using AWS Cognito.
    ///
    /// This method translates the `AuthRequest` into an `AuthUser` and delegates
    /// the signup process to the Cognito repository.
    ///
    /// # Arguments
    ///
    /// * `auth` - An `AuthRequest` containing the new user's information.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a `()` on success, or an `AuthError` on failure.
    async fn signup_user(&self, auth: AuthRequest) -> Result<(), AuthError> {
        let user = AuthUser::new("".to_string(), auth.email, auth.password, "".to_string());
        self.cognito_repository.signup_user(&user).await?;
        Ok(())
    }

    /// Confirms a user's signup using AWS Cognito.
    ///
    /// This method translates the `AuthRequest` into an `AuthUser` and delegates
    /// the confirmation process to the Cognito repository.
    ///
    /// # Arguments
    ///
    /// * `auth` - An `AuthRequest` containing the user's information and verification code.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a `()` on success, or an `AuthError` on failure.
    async fn confirm_code(&self, auth: AuthRequest) -> Result<(), AuthError> {
        let user = AuthUser::new("".to_string(), auth.email, auth.password, auth.verify_code);
        self.cognito_repository.confirm_code(&user).await?;
        Ok(())
    }
}

// ===== TEST SECTION START =====


#[cfg(test)]
mod test {
    use super::*;
    use mockall::mock;

    mock! {
        CognitoRepository {}
        #[async_trait]
        impl CognitoRepository for CognitoRepository {
            async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError>;
            async fn signup_user(&self, auth: &AuthUser) -> Result<(), AuthError>;
            async fn confirm_code(&self, auth: &AuthUser) -> Result<(), AuthError>;
        }
    }
    #[tokio::test]
    async fn test_authenticate_user_success() {
        let mut mock_repo = MockCognitoRepository::new();
        mock_repo
            .expect_authenticate_user()
            .with(mockall::predicate::function(|auth: &AuthUser| {
                auth.email == "test@example.com" && auth.password == "password123"
            }))
            .times(1)
            .returning(|_| {
                Ok(Token::new(
                    "jwt_token".to_string(),
                    "refresh_token".to_string(),
                ))
            });

        let auth_service = AuthServiceImpl::new(Arc::new(mock_repo));

        let auth_request = AuthRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            verify_code: "".to_string(),
        };

        let result = auth_service.authenticate_user(auth_request).await;
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.jwt, "jwt_token");
        assert_eq!(token.refresh, "refresh_token");
    }

    #[tokio::test]
    async fn test_authenticate_user_failed() {
        let mut mock_repo = MockCognitoRepository::new();
        mock_repo
            .expect_authenticate_user()
            .with(mockall::predicate::function(|auth: &AuthUser| {
                auth.email == "test@example.com" && auth.password == "password123"
            }))
            .times(1)
            .returning(|_| Err(AuthError::AuthenticationFailed));
        let auth_request = AuthRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            verify_code: "".to_string(),
        };
        let auth_service = AuthServiceImpl::new(Arc::new(mock_repo));
        let result = auth_service
            .authenticate_user(auth_request)
            .await
            .map_err(|_| AuthError::AuthenticationFailed);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_signup_user_success() {
        let mut mock_repo = MockCognitoRepository::new();

        mock_repo
            .expect_signup_user()
            .with(mockall::predicate::function(|auth: &AuthUser| {
                auth.email == "test@example.com" && auth.password == "password123"
            }))
            .times(1)
            .returning(move |_| Ok(()));

        let auth_request = AuthRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            verify_code: "".to_string(),
        };

        let auth_service = AuthServiceImpl::new(Arc::new(mock_repo));
        let result = auth_service.signup_user(auth_request).await;
        assert!(result.is_ok())
    }

    #[tokio::test]
    async fn test_signup_user_failed() {
        let mut mock_repo = MockCognitoRepository::new();
        mock_repo
            .expect_signup_user()
            .with(mockall::predicate::function(|auth: &AuthUser| {
                auth.email == "test@example.com" && auth.password == "password123"
            }))
            .times(1)
            .returning(|_| Err(AuthError::AuthenticationFailed));

        let auth_request = AuthRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            verify_code: "".to_string(),
        };

        let auth_service = AuthServiceImpl::new(Arc::new(mock_repo));
        let result = auth_service
            .signup_user(auth_request)
            .await
            .map_err(|_| AuthError::AuthenticationFailed);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_confirm_code_success() {
        let mut mock_repo = MockCognitoRepository::new();
        mock_repo
            .expect_confirm_code()
            .with(mockall::predicate::function(|auth: &AuthUser| {
                auth.email == "test@example.com" && auth.password == "password123"
            }))
            .times(1)
            .returning(|_| Ok(()));

        let auth_request = AuthRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            verify_code: "123456".to_string(),
        };

        let auth_service = AuthServiceImpl::new(Arc::new(mock_repo));
        let result = auth_service
            .confirm_code(auth_request)
            .await
            .map_err(|_| AuthError::AuthenticationFailed);

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_confirm_code_failed() {
        let mut mock_repo = MockCognitoRepository::new();
        mock_repo
            .expect_confirm_code()
            .with(mockall::predicate::function(|auth: &AuthUser| {
                auth.email == "test@example.com" && auth.password == "password123"
            }))
            .times(1)
            .returning(|_| Err(AuthError::AuthenticationFailed));

        let auth_request = AuthRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            verify_code: "123456".to_string(),
        };

        let auth_service = AuthServiceImpl::new(Arc::new(mock_repo));
        let result = auth_service
            .confirm_code(auth_request)
            .await
            .map_err(|_| AuthError::AuthenticationFailed);

        assert!(result.is_err());
    }
}
