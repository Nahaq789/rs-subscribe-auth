use std::sync::Arc;

use axum::async_trait;

use crate::{
    adapter::aws::{client::cognito_client::CognitoClient, provider::AwsProvider},
    domain::entity::auth_user::AuthUser,
    exception::auth_error::AuthError,
};

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn auth_by_cognito(&self, auth: AuthUser) -> Result<(), AuthError>;
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
    async fn auth_by_cognito(&self, auth: AuthUser) -> Result<(), AuthError> {
        let cognito = self.cognito.get_aws_config().await.unwrap();
        cognito
            .client
            .initiate_auth()
            .auth_flow(aws_sdk_cognitoidentityprovider::types::AuthFlowType::UserPasswordAuth)
            .client_id(cognito.client_id)
            .auth_parameters("USERNAME", auth.email)
            .auth_parameters("PASSWORD", auth.password)
            .send()
            .await
            .map_err(|_| AuthError::AuthenticationFailed)?;

        Ok(())
    }
}
