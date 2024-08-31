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

/// Implements the `IntoResponse` trait for `AuthError`.
/// This allows `AuthError` to be converted into an HTTP response.
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::AuthenticationFailed => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::TokenMissing => (StatusCode::UNAUTHORIZED, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        status.into_response()
    }
}

/// Handles the sign-in (login) process.
///
/// # Arguments
///
/// * `module` - An `Arc` wrapped `AuthService` implementation.
/// * `payload` - The JSON payload containing the user's credentials.
///
/// # Returns
///
/// Returns a `Result` containing the authentication result or an `AuthError`.
pub async fn signin(
    Extension(module): Extension<Arc<dyn AuthService>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let user = AuthUser::new("".to_string(), payload.email, payload.password);
    let token = module.authenticate_user(&user).await?;

    let result = AuthResult::new(&token.jwt, &token.refresh, 200);

    Ok((StatusCode::OK, Json(result)))
}

/// Handles the sign-up process and then signs in the new user.
///
/// # Arguments
///
/// * `module` - An `Arc` wrapped `AuthService` implementation.
/// * `payload` - The JSON payload containing the user's registration information.
///
/// # Returns
///
/// Returns a `Result` containing the authentication result for the new user or an `AuthError`.
pub async fn signup(
    Extension(module): Extension<Arc<dyn AuthService>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let user = AuthUser::new("".to_string(), payload.email, payload.password);
    module.signup_user(&user).await?;

    // let result = AuthResult::new(&token.jwt, &token.refresh, 200);
    Ok((StatusCode::OK, Json(("User Created", 200))))
}
