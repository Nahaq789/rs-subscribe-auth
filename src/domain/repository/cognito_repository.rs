use aws_sdk_cognitoidentityprovider::operation::{
    confirm_sign_up::ConfirmSignUpOutput, sign_up::SignUpOutput,
};
use axum::async_trait;

use crate::{
    domain::entity::{auth_user::AuthUser, token::Token},
    exception::auth_error::AuthError,
};

/// CognitoRepository trait defines the interface for interacting with AWS Cognito
/// for user authentication and management.
#[async_trait]
#[mockall::automock]
pub trait CognitoRepository: Send + Sync + 'static {
    /// Authenticates a user against AWS Cognito.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an AuthUser containing the user's credentials.
    ///
    /// # Returns
    ///
    /// Returns a Result containing a Token on success, or an AuthError on failure.
    async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError>;

    /// Signs up a new user in AWS Cognito.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an AuthUser containing the new user's information.
    ///
    /// # Returns
    ///
    /// Returns a Result containing a SignUpOutput on success, or an AuthError on failure.
    async fn signup_user(&self, auth: &AuthUser) -> Result<SignUpOutput, AuthError>;

    /// Confirms a user's signup using a confirmation code.
    ///
    /// # Arguments
    ///
    /// * `auth` - A reference to an AuthUser containing the user's information and confirmation code.
    ///
    /// # Returns
    ///
    /// Returns a Result containing a ConfirmSignUpOutput on success, or an AuthError on failure.
    async fn confirm_code(&self, auth: &AuthUser) -> Result<ConfirmSignUpOutput, AuthError>;
}
