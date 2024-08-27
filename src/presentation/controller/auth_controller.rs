use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};

use crate::{
    application::auth::auth_service::AuthService,
    domain::entity::auth_user::AuthUser,
    exception::auth_error::AuthError,
    presentation::dto::{auth_request::AuthRequest, auth_result::AuthResult},
};

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::AuthenticationFailed => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::ConfigurationError => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AuthError::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AuthError::TokenMissing => (StatusCode::UNAUTHORIZED, self.to_string()),
        };
        status.into_response()
    }
}

pub async fn signin(
    Extension(module): Extension<Arc<dyn AuthService>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let user = AuthUser::new("unko".to_string(), payload.email, payload.password);
    let token = module.authenticate_user(user).await?;

    let result = AuthResult::new(&token.jwt, &token.refresh, 200);

    Ok((StatusCode::OK, Json(result)))
}
