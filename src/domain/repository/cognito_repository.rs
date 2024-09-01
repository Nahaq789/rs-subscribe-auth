use aws_sdk_cognitoidentityprovider::operation::{
    confirm_sign_up::ConfirmSignUpOutput, sign_up::SignUpOutput,
};
use axum::async_trait;

use crate::{
    domain::entity::{auth_user::AuthUser, token::Token},
    exception::auth_error::AuthError,
};

#[async_trait]
pub trait CognitoRepository: Send + Sync + 'static {
    async fn authenticate_user(&self, auth: &AuthUser) -> Result<Token, AuthError>;
    async fn signup_user(&self, auth: &AuthUser) -> Result<SignUpOutput, AuthError>;
    async fn confirm_code(&self, auth: &AuthUser) -> Result<ConfirmSignUpOutput, AuthError>;
}
