use crate::{
    exception::auth_error::AuthError,
    module::module::DynAuthService,
    presentation::dto::{auth_request::AuthRequest, auth_result::AuthResult},
};
use axum::{http::StatusCode, response::{IntoResponse, Response}, Extension, Json};


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
mod test {
    use super::*;
    use crate::application::auth::auth_service::AuthService;
    use crate::domain::entity::token::Token;
    use crate::module::module::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::string::String;
    use std::sync::Arc;
    use tower::ServiceExt;

    mockall::mock! {
        AuthService {}
        #[axum::async_trait]
        impl AuthService for AuthService {
            async fn authenticate_user(&self, auth: AuthRequest) -> Result<Token, AuthError>;
            async fn signup_user(&self, auth: AuthRequest) -> Result<(), AuthError>;
            async fn confirm_code(&self, auth: AuthRequest) -> Result<(), AuthError>;
        }
    }

    async fn app(auth_service: Arc<dyn AuthService + Send + Sync>) -> Router {
        let state = AppState::new_with_auth_service(auth_service);

        Router::new().route("/api/v1/auth/signin", axum::routing::post(signin)).layer(Extension(state.auth_service))
    }

    #[tokio::test]
    async fn test_signin_success() {
        let mut mock_service = MockAuthService::new();
        let result_jwt = String::from("hogehogehoge");
        let result_refresh = String::from("fugafugafuga");
        mock_service
            .expect_authenticate_user()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| Ok(Token::new(
                "hogehogehoge".to_string(),
                "fugafugafuga".to_string(),
            )));

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };

        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/signin")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;


        let response = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["jwt"], result_jwt);
        assert_eq!(body["refresh"], result_refresh);
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
                Err(AuthError::AuthenticationFailed)
            });

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };

        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/signin")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, AuthError::AuthenticationFailed.to_string())
    }
}


