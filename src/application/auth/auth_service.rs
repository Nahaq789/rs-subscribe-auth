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
    /// * `auth` - A reference to an `AuthUser` containing the user's credentials.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(Token)` containing the authentication tokens if successful.
    /// - `Err(AuthError)` if authentication fails for any reason.
    async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError>;

    /// Registers a new user with the authentication service.
    ///
    /// This method attempts to create a new user account in the backend authentication
    /// service using the provided user information.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an `AuthUser` containing the new user's information.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(SignUpOutput)` containing the signup result if successful.
    /// - `Err(AuthError)` if signup fails for any reason (e.g., user already exists).
    async fn signup_user(&self, auth: &AuthUser) -> Result<SignUpOutput, AuthError>;

    /// Performs a signup operation followed immediately by a signin attempt.
    ///
    /// This method combines the signup and signin processes into a single operation.
    /// It first attempts to register the user, and if successful and the user is
    /// automatically confirmed, it proceeds to authenticate the user.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an `AuthUser` containing the user's information.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(Token)` containing the authentication tokens if both signup and signin are successful.
    /// - `Err(AuthError)` if either the signup or signin process fails, or if the user requires confirmation.
    async fn signup_then_signin(&self, auth: &AuthUser) -> Result<Token, AuthError>;
}

/// Implements the AuthService trait using AWS Cognito as the authentication backend.
///
/// This struct provides concrete implementations for user authentication, signup,
/// and combined signup-signin processes using AWS Cognito. It encapsulates the
/// complexity of interacting with Cognito, including the generation of secret hashes
/// and handling of Cognito-specific errors.
pub struct AuthServiceImpl {
    cognito: Arc<dyn AwsProvider<CognitoClient>>,
}

impl AuthServiceImpl {
    /// Creates a new instance of AuthServiceImpl.
    ///
    /// # Arguments
    ///
    /// * `cognito` - An Arc-wrapped trait object providing access to AWS Cognito configuration and client.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `AuthServiceImpl`.
    pub fn new(cognito: Arc<dyn AwsProvider<CognitoClient>>) -> Self {
        AuthServiceImpl { cognito }
    }

    /// Generates a client secret hash required for certain Cognito operations.
    ///
    /// This method creates a hash using HMAC-SHA256, combining the user's email,
    /// Cognito client ID, and client secret. This hash is used to verify requests
    /// to Cognito, adding an extra layer of security.
    ///
    /// # Arguments
    ///
    /// * `user_email` - The email address of the user.
    /// * `client_id` - The Cognito client ID.
    /// * `client_secret` - The Cognito client secret.
    ///
    /// # Returns
    ///
    /// Returns a base64-encoded string representing the generated hash.
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

    /// Attempts to sign up a new user and then immediately sign them in.
    ///
    /// This method combines the signup and signin processes. It first tries to register
    /// the user with Cognito. If successful and the user is automatically confirmed,
    /// it proceeds to authenticate the user. This is useful for implementing a streamlined
    /// registration process where users can start using the service immediately after signup.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an `AuthUser` containing the user's email and password.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(Token)` containing the authentication tokens if both signup and signin are successful.
    /// - `Err(AuthError)` if either the signup or signin process fails, or if the user requires confirmation.
    ///
    /// # Errors
    ///
    /// This method can return various `AuthError` variants, including:
    /// - Any error that can be returned by `signup_user` or `authenticate_user`.
    /// - `AuthError::InternalServerError` if the user is successfully signed up but requires confirmation,
    ///   preventing immediate signin.
    ///
    /// # Note
    ///
    /// This method assumes that successful signup results in an automatically confirmed user.
    /// If your Cognito user pool is configured to require manual confirmation (e.g., via email),
    /// this method will always return an error for new signups.
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
