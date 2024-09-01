use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};

use crate::{
    exception::auth_error::AuthError,
    module::module::DynAuthService,
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
    Extension(module): Extension<DynAuthService>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let token = module.authenticate_user(payload).await?;

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
    Extension(module): Extension<DynAuthService>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    module.signup_user(payload).await?;

    Ok((StatusCode::OK, Json(("User Created", 200))))
}
