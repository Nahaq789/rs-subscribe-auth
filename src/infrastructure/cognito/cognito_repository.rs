use std::sync::Arc;

use aws_sdk_cognitoidentityprovider::{
    error::SdkError,
    operation::{
        confirm_sign_up::ConfirmSignUpOutput,
        sign_up::{SignUpError, SignUpOutput},
    },
    types::AttributeType,
};
use axum::async_trait;

use crate::{
    adapter::aws::{client::cognito_client::CognitoClient, provider::AwsProvider},
    domain::{
        entity::{auth_user::AuthUser, token::Token},
        repository::cognito_repository::CognitoRepository,
    },
    exception::auth_error::AuthError,
};

/// Implements the CognitoRepository trait using AWS SDK for Cognito.
///
/// This struct provides concrete implementations for user authentication, signup,
/// and signup confirmation processes using AWS Cognito. It encapsulates the
/// complexity of interacting with Cognito, including the generation of secret hashes
/// and handling of Cognito-specific errors.
#[derive(Clone)]
pub struct CognitoRepositoryImpl {
    /// The AWS provider for Cognito client, wrapped in an Arc for thread-safe sharing.
    cognito: Arc<dyn AwsProvider<CognitoClient>>,
}

impl CognitoRepositoryImpl {
    /// Creates a new instance of CognitoRepositoryImpl.
    ///
    /// # Arguments
    ///
    /// * `cognito` - An Arc-wrapped instance of a type implementing the AwsProvider trait for CognitoClient,
    ///               providing access to AWS Cognito configuration and client.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `CognitoRepositoryImpl`.
    pub fn new(cognito: Arc<dyn AwsProvider<CognitoClient>>) -> Self {
        CognitoRepositoryImpl { cognito }
    }
}

#[async_trait]
impl CognitoRepository for CognitoRepositoryImpl {
    /// Authenticates a user using AWS Cognito.
    ///
    /// This method initiates an authentication flow with Cognito using the provided
    /// user credentials. It generates a secret hash, sends the authentication request
    /// to Cognito, and processes the response to extract the necessary tokens.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an `AuthUser` containing the user's email and password.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(Token)` containing the JWT and refresh token if authentication is successful.
    /// - `Err(AuthError)` if authentication fails for any reason, such as invalid credentials
    ///   or Cognito service errors.
    ///
    /// # Errors
    ///
    /// This method can return various `AuthError` variants, including:
    /// - `AuthError::ConfigurationError` if there's an issue with the AWS configuration.
    /// - `AuthError::AuthenticationFailed` if Cognito rejects the authentication attempt.
    /// - `AuthError::TokenMissing` if the expected tokens are not present in Cognito's response.
    async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError> {
        let cognito = self
            .cognito
            .get_aws_config()
            .await
            .map_err(|_| AuthError::ConfigurationError)?;

        let secret_hash = CognitoClient::client_secret_hash(
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

    /// Registers a new user with AWS Cognito.
    ///
    /// This method attempts to create a new user account in Cognito using the provided
    /// user information. It sets up the necessary attributes (e.g., email), generates
    /// a secret hash, and sends a signup request to Cognito.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an `AuthUser` containing the new user's email and password.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(SignUpOutput)` containing Cognito's response to the signup request if successful.
    /// - `Err(AuthError)` if the signup process fails for any reason.
    ///
    /// # Errors
    ///
    /// This method can return various `AuthError` variants, including:
    /// - `AuthError::ConfigurationError` if there's an issue with the AWS configuration.
    /// - `AuthError::UserAlreadyExists` if a user with the given email already exists.
    /// - `AuthError::InvalidPassword` if the provided password doesn't meet Cognito's requirements.
    /// - `AuthError::InternalServerError` for other types of errors, including AWS SDK errors.
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

        let secret_hash = CognitoClient::client_secret_hash(
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

    /// Confirms a user's signup using a verification code.
    ///
    /// This method is typically used to complete the registration process by verifying
    /// the user's email or phone number with a code sent by Cognito during the signup process.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an `AuthUser` containing the user's email and verification code.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(ConfirmSignUpOutput)` if the confirmation is successful.
    /// - `Err(AuthError)` if the confirmation fails for any reason.
    ///
    /// # Errors
    ///
    /// This method can return various `AuthError` variants, including:
    /// - `AuthError::ConfigurationError` if there's an issue with the AWS configuration.
    /// - `AuthError::AuthenticationFailed` if the verification code is invalid or expired.
    async fn confirm_code(&self, auth: &AuthUser) -> Result<ConfirmSignUpOutput, AuthError> {
        let cognito = self
            .cognito
            .get_aws_config()
            .await
            .map_err(|_| AuthError::ConfigurationError)?;

        let secret_hash = CognitoClient::client_secret_hash(
            &auth.email,
            &cognito.client_id,
            &cognito.client_secret,
        );

        let confirm_result = cognito
            .client
            .confirm_sign_up()
            .client_id(&cognito.client_id)
            .username(&auth.email)
            .secret_hash(secret_hash)
            .confirmation_code(&auth.verify_code)
            .send()
            .await
            .map_err(|e| {
                log::error!("Verify Confirm error: {:?}", e);
                AuthError::AuthenticationFailed
            })?;

        Ok(confirm_result)
    }
}
