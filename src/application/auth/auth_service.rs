use std::sync::Arc;

use axum::async_trait;
use Ok;

use crate::{
    adapter::aws::{client::cognito_client::CognitoClient, provider::AwsProvider},
    domain::entity::{auth_user::AuthUser, token::Token},
    exception::auth_error::AuthError,
};

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn authenticate_user(&self, auth: AuthUser) -> Result<Token, AuthError>;
}

pub struct AuthServiceImpl {
    cognito: Arc<dyn AwsProvider<CognitoClient>>,
}

impl AuthServiceImpl {
    pub fn new(cognito: Arc<dyn AwsProvider<CognitoClient>>) -> Self {
        AuthServiceImpl { cognito }
    }
}

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn authenticate_user(&self, auth: AuthUser) -> Result<Token, AuthError> {
        let cognito = self
            .cognito
            .get_aws_config()
            .await
            .map_err(|_| AuthError::ConfigurationError)?;
        let authentication = cognito
            .client
            .initiate_auth()
            .auth_flow(aws_sdk_cognitoidentityprovider::types::AuthFlowType::UserPasswordAuth)
            .client_id(&cognito.client_id)
            .auth_parameters("USERNAME", &auth.email)
            .auth_parameters("PASSWORD", &auth.password)
            .send()
            .await
            .map_err(|e| {
                log::error!("Authentication failed: {:?}", e);
                AuthError::AuthenticationFailed
            })?;

        if let Some(challenge_name) = authentication.challenge_name() {
            log::warn!("Authentication challenge received: {:?}", challenge_name);
            return Err(AuthError::AuthenticationFailed);
        }

        let authenticate_result = authentication.authentication_result().ok_or_else(|| {
            log::error!("No authentication result in response");
            AuthError::AuthenticationFailed
        })?;

        let jwt = authenticate_result
            .access_token()
            .ok_or_else(|| {
                log::error!("Access token missing from authentication result");
                AuthError::TokenMissing
            })?
            .to_string();

        let refresh = authenticate_result
            .refresh_token()
            .ok_or_else(|| {
                log::error!("Refresh token missing from authentication result");
                AuthError::TokenMissing
            })?
            .to_string();

        let token = Token::new(jwt, refresh);

        Ok(token)
    }
}
