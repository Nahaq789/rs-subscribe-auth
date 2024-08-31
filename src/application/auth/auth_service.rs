use std::sync::Arc;

use aws_sdk_cognitoidentityprovider::{
    error::SdkError,
    operation::sign_up::{SignUpError, SignUpOutput},
    types::AttributeType,
};
use axum::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use Ok;

use crate::{
    adapter::aws::{client::cognito_client::CognitoClient, provider::AwsProvider},
    domain::entity::{auth_user::AuthUser, token::Token},
    exception::auth_error::AuthError,
};

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError>;
    async fn signup_user(&self, auth: &AuthUser) -> Result<SignUpOutput, AuthError>;
    async fn signup_then_signin(&self, auth: &AuthUser) -> Result<Token, AuthError>;
}

pub struct AuthServiceImpl {
    cognito: Arc<dyn AwsProvider<CognitoClient>>,
}

impl AuthServiceImpl {
    pub fn new(cognito: Arc<dyn AwsProvider<CognitoClient>>) -> Self {
        AuthServiceImpl { cognito }
    }

    fn client_secret_hash(user_email: &str, client_id: &str, client_secret: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(client_secret.as_bytes())
            .expect("HMAC can take key of any size");

        mac.update(user_email.as_bytes());
        mac.update(client_id.as_bytes());
        let result = mac.finalize();
        base64::encode(result.into_bytes())
    }
}

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError> {
        let cognito = self
            .cognito
            .get_aws_config()
            .await
            .map_err(|_| AuthError::ConfigurationError)?;

        let secret_hash = AuthServiceImpl::client_secret_hash(
            &auth.email,
            &cognito.client_id,
            &cognito.client_secret,
        );

        let authentication = cognito
            .client
            .initiate_auth()
            .auth_flow(aws_sdk_cognitoidentityprovider::types::AuthFlowType::UserPasswordAuth)
            .client_id(&cognito.client_id)
            .auth_parameters("USERNAME", &auth.email)
            .auth_parameters("PASSWORD", &auth.password)
            .auth_parameters("SECRET_HASH", &secret_hash)
            .send()
            .await
            .map_err(|e| {
                log::error!("Authentication failed: {:?}", e);
                AuthError::AuthenticationFailed
            })?;

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

    async fn signup_user(&self, auth: &AuthUser) -> Result<SignUpOutput, AuthError> {
        let cognito = self
            .cognito
            .get_aws_config()
            .await
            .map_err(|_| AuthError::ConfigurationError)?;

        let email_attribute = AttributeType::builder()
            .name("email")
            .value(&auth.email)
            .build()
            .map_err(|e| {
                log::error!("Failed to build email attribute: {:?}", e);
                AuthError::InternalServerError(format!("Failed to build email attribute: {:?}", e))
            })?;

        let secret_hash = AuthServiceImpl::client_secret_hash(
            &auth.email,
            &cognito.client_id,
            &cognito.client_secret,
        );

        cognito
            .client
            .sign_up()
            .client_id(&cognito.client_id)
            .username(&auth.email)
            .password(&auth.password)
            .secret_hash(secret_hash)
            .user_attributes(email_attribute)
            .send()
            .await
            .map_err(|e| {
                log::error!("Signup error: {:?}", e);
                match e {
                    SdkError::ServiceError(service_error) => match service_error.err() {
                        SignUpError::UsernameExistsException(_) => AuthError::UserAlreadyExists,
                        SignUpError::InvalidPasswordException(_) => AuthError::InvalidPassword,
                        _ => AuthError::InternalServerError(format!(
                            "Unhandled Cognito error: {:?}",
                            service_error
                        )),
                    },
                    _ => AuthError::InternalServerError(format!("AWS SDK error: {:?}", e)),
                }
            })
    }

    async fn signup_then_signin(&self, auth: &AuthUser) -> Result<Token, AuthError> {
        let signup_result = self.signup_user(&auth).await?;
        if signup_result.user_confirmed() {
            Ok(self.authenticate_user(&auth).await?)
        } else {
            log::error!("User signup successful, but confirmation required");
            Err(AuthError::InternalServerError(
                "User signup successful, but confirmation required".into(),
            ))
        }
    }
}
