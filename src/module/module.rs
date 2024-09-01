use std::sync::Arc;

use crate::{
    adapter::aws::client::cognito_client::CognitoClient,
    application::auth::auth_service::{AuthService, AuthServiceImpl},
    infrastructure::cognito::cognito_repository::CognitoRepositoryImpl,
};

pub type DynAuthService = Arc<dyn AuthService + Send + Sync>;

pub struct AppState {
    pub auth_service: DynAuthService,
}

impl AppState {
    pub async fn new() -> Self {
        // Initialize the Cognito client from environment variables
        let cognito = Arc::new(CognitoClient::from_env().await.unwrap());

        // Initialize the Cognito Repository
        let cognito_repository = Arc::new(CognitoRepositoryImpl::new(cognito));

        // Create the authentication service
        let auth_service = Arc::new(AuthServiceImpl::new(cognito_repository));

        Self { auth_service }
    }
}
