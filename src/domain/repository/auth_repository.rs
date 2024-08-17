use axum::{async_trait, Error};

use crate::domain::entity::auth_user::AuthUser;

#[async_trait]
pub trait AuthRepository {
    async fn get_by_name(&self, name: String) -> Result<Option<AuthUser>, Error>;
    async fn get_by_name_and_pass(
        &self,
        name: String,
        password: String,
    ) -> Result<Option<AuthUser>, Error>;
}
