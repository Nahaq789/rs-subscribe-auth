use axum::async_trait;

use crate::{
    adapter::aws::config::AwsConfig, domain::entity::auth_user::AuthUser,
    exception::auth_error::AuthError,
};

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn auth_by_cognito(&self, auth: AuthUser) -> Result<(), AuthError>;
}

pub struct AuthServiceImpl {}

impl AuthServiceImpl {
    pub fn new() -> Self {
        AuthServiceImpl {}
    }
}

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn auth_by_cognito(&self, auth: AuthUser) -> Result<(), AuthError> {
        let unko = AwsConfig::get_env_value().unwrap();
        println!("{}", unko.user_pool_id);

        Ok(())
    }
}
