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

pub async fn confirm_code(
    Extension(module): Extension<DynAuthService>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    module.confirm_code(payload).await?;

    Ok((StatusCode::OK, Json(("Confirm Your Account", 200))))
}

// ===== TEST SECTION START =====
#[cfg(test)]
mockall::mock! {
    AuthService {}
    #[axum::async_trait]
    impl crate::application::auth::auth_service::AuthService for AuthService {
        async fn authenticate_user(&self, auth: AuthRequest) -> Result<crate::domain::entity::token::Token, AuthError>;
        async fn signup_user(&self, auth: AuthRequest) -> Result<(), AuthError>;
        async fn confirm_code(&self, auth: AuthRequest) -> Result<(), AuthError>;
    }
}

#[tokio::test]
async fn test_signin_failed() {
    let mut mock_service = MockAuthService::new();
    mock_service
        .expect_authenticate_user()
        .with(mockall::predicate::function(|auth: &AuthRequest| {
            auth.email == "hogehoge@email.com"
                && auth.password == "hogehoge"
                && auth.verify_code == "hogehoge12345"
        }))
        .returning(|_| {
            Ok(crate::domain::entity::token::Token::new(
                "jwt".to_string(),
                "refresh".to_string(),
            ))
        });

    let auth_request = AuthRequest {
        email: "hogehoge@email.com".to_string(),
        password: "hogehoge".to_string(),
        verify_code: "hogehoge12345".to_string(),
    };

    let state = crate::module::module::AppState::new().await;

    let result = signin(Extension(state.auth_service), Json(auth_request))
        .await
        .map_err(|_| AuthError::AuthenticationFailed);

    assert!(result.is_err())
}
