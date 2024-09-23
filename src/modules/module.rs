use std::sync::Arc;

use crate::{
    adapter::aws::client::cognito_client::CognitoClient,
    application::auth::auth_service::{AuthService, AuthServiceImpl},
    infrastructure::cognito::cognito_repository::CognitoRepositoryImpl,
};

/// A type alias for a thread-safe, dynamically dispatched AuthService.
///
/// This type represents an Arc-wrapped trait object of AuthService that can be
/// safely shared between threads. It's used to provide a unified interface for
/// authentication operations throughout the application.
pub type DynAuthService = Arc<dyn AuthService + Send + Sync>;

/// Represents the global state of the application.
///
/// AppState encapsulates all the shared resources and services that need to be
/// accessible throughout the application's lifetime. It's typically created once
/// during application startup and then shared across different parts of the app.
pub struct AppState {
    /// The authentication service, wrapped in an Arc for thread-safe sharing.
    ///
    /// This service provides methods for user authentication, registration, and
    /// other identity-related operations using AWS Cognito.
    pub auth_service: DynAuthService,
}

impl AppState {
    /// Creates a new instance of AppState.
    ///
    /// This method initializes all the necessary components of the application state,
    /// including setting up the AWS Cognito client, creating the Cognito repository,
    /// and instantiating the authentication service.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `AppState` with all its components initialized.
    ///
    /// # Panics
    ///
    /// This method will panic if it fails to initialize the Cognito client from
    /// environment variables. In a production environment, you might want to
    /// handle this error more gracefully.
    pub async fn new() -> Self {
        // Initialize the Cognito client from environment variables
        let cognito = Arc::new(CognitoClient::from_env().await.unwrap());

        // Initialize the Cognito Repository
        let cognito_repository = Arc::new(CognitoRepositoryImpl::new(cognito));

        // Create the authentication service
        let auth_service = Arc::new(AuthServiceImpl::new(cognito_repository));

        Self { auth_service }
    }

    /// Creates a new instance of AppState with a custom AuthService.
    ///
    /// This method is particularly useful for testing, where you might want to
    /// inject a mock AuthService.
    ///
    /// # Arguments
    ///
    /// * `auth_service` - An Arc-wrapped trait object implementing AuthService
    ///
    /// # Returns
    ///
    /// Returns a new instance of `AppState` with the provided AuthService.
    #[cfg(test)]
    pub fn new_with_auth_service(auth_service: Arc<dyn AuthService>) -> Self {
        Self { auth_service }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::Any;

    #[tokio::test]
    async fn test_app_state_create_success() {
        let result = AppState::new().await;

        assert_eq!(
            result.type_name().to_string(),
            AppState::new().await.type_name().to_string()
        );
        assert_eq!(
            result.auth_service.type_name().to_string(),
            AppState::new().await.auth_service.type_name().to_string()
        )
    }
}
