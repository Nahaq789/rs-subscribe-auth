use crate::domain::exception::auth_domain_exception::AuthDomainException;
use crate::exception::application_exception::ApplicationException;
use crate::presentation::dto::error_response::ErrorResponse;
use crate::{
    exception::auth_exception::AuthException,
    modules::module::DynAuthService,
    presentation::dto::{auth_request::AuthRequest, auth_result::AuthResult},
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;

/// Implements the `IntoResponse` trait for `ApplicationError`.
/// This allows `ApplicationError` to be converted into an HTTP response.
impl IntoResponse for ApplicationException {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApplicationException::AuthError(AuthException::AuthenticationFailed(..)) => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            ApplicationException::AuthError(AuthException::TokenMissing) => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            ApplicationException::AuthDomainError(AuthDomainException::ValidateFailed) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        let body = Json(ErrorResponse::new(status, &error_message));
        (status, body).into_response()
    }
}

/// Handles the sign-in (login) process.
///
/// # Arguments
///
/// * `modules` - An `Arc` wrapped `AuthService` implementation.
/// * `payload` - The JSON payload containing the user's credentials.
///
/// # Returns
///
/// Returns a `Result` containing the authentication result or an `ApplicationError`.
pub async fn signin(
    Extension(module): Extension<DynAuthService>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, ApplicationException> {
    let token = module.authenticate_user(payload).await?;

    let result = AuthResult::new(&token.jwt, &token.refresh, 200);

    Ok((StatusCode::OK, Json(result)))
}

/// Handles the sign-up process and then signs in the new user.
///
/// # Arguments
///
/// * `modules` - An `Arc` wrapped `AuthService` implementation.
/// * `payload` - The JSON payload containing the user's registration information.
///
/// # Returns
///
/// Returns a `Result` containing the authentication result for the new user or an `ApplicationError`.
pub async fn signup(
    Extension(module): Extension<DynAuthService>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, ApplicationException> {
    module.signup_user(payload).await?;
    let response = json! {
        {"message": "User Created", "status_code": 200}
    };

    Ok((StatusCode::OK, Json(response)))
}

pub async fn confirm_code(
    Extension(module): Extension<DynAuthService>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, ApplicationException> {
    module.confirm_code(payload).await?;

    let response = json! {
        {"message": "Confirm Your Account", "status_code": 200}
    };
    Ok((StatusCode::OK, Json(response)))
}

// ===== TEST SECTION START =====
#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::auth::auth_service::AuthService;
    use crate::domain::entity::token::Token;
    use crate::modules::module::AppState;
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
            async fn authenticate_user(&self, auth: AuthRequest) -> Result<Token, ApplicationException>;
            async fn signup_user(&self, auth: AuthRequest) -> Result<(), ApplicationException>;
            async fn confirm_code(&self, auth: AuthRequest) -> Result<(), ApplicationException>;
        }
    }

    async fn app(auth_service: Arc<dyn AuthService + Send + Sync>) -> Router {
        let state = AppState::new_with_auth_service(auth_service);

        Router::new()
            .route("/api/v1/auth/signin", axum::routing::post(signin))
            .route("/api/v1/auth/signup", axum::routing::post(signup))
            .route("/api/v1/auth/confirm", axum::routing::post(confirm_code))
            .layer(Extension(state.auth_service))
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
            .returning(|_| {
                Ok(Token::new(
                    "hogehogehoge".to_string(),
                    "fugafugafuga".to_string(),
                ))
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
                Err(ApplicationException::AuthError(
                    AuthException::AuthenticationFailed("hoge".to_string()),
                ))
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
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            body["message"],
            AuthException::AuthenticationFailed("hoge".to_string()).to_string()
        )
    }

    #[tokio::test]
    async fn test_signup_success() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_signup_user()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| Ok(()));

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/signup")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "User Created");
        assert_eq!(body["status_code"], 200);
    }

    #[tokio::test]
    async fn test_signup_user_already_exists() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_signup_user()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| Err(ApplicationException::AuthError(AuthException::UserAlreadyExists)));

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/signup")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();


        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        println!("{:?}", &body);
        assert_eq!(body["message"], "User already exists: An account with this email address is already registered");
        assert_eq!(body["status_code"], 500);
    }

    #[tokio::test]
    async fn test_signup_invalid_password() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_signup_user()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| Err(ApplicationException::AuthError(AuthException::InvalidPassword)));

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/signup")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();


        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["message"], "Invalid password: Password does not meet the required criteria");
        assert_eq!(body["status_code"], 500);
    }

    #[tokio::test]
    async fn test_signup_failed() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_signup_user()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| {
                Err(ApplicationException::AuthError(
                    AuthException::InternalServerError("test".to_string()),
                ))
            });

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/signup")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "Internal Server Error: test");
    }

    #[tokio::test]
    async fn test_confirm_code_success() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_confirm_code()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| Ok(()));

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/confirm")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "Confirm Your Account");
        assert_eq!(body["status_code"], 200);
    }

    #[tokio::test]
    async fn test_confirm_code_failed() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_confirm_code()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com"
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| {
                Err(ApplicationException::AuthError(
                    AuthException::AuthenticationFailed(String::from("hoge")),
                ))
            });

        let auth_request = AuthRequest {
            email: "hogehoge@email.com".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/confirm")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "Authentication failed: hoge")
    }

    #[tokio::test]
    async fn test_return_auth_domain_exception() {
        let mut mock_service = MockAuthService::new();
        mock_service
            .expect_confirm_code()
            .with(mockall::predicate::function(|auth: &AuthRequest| {
                auth.email == "hogehoge@email.com........."
                    && auth.password == "hogehoge"
                    && auth.verify_code == "hogehoge12345"
            }))
            .times(1)
            .returning(|_| {
                Err(ApplicationException::AuthDomainError(
                    AuthDomainException::ValidateFailed,
                ))
            });

        let auth_request = AuthRequest {
            email: "hogehoge@email.com.........".to_string(),
            password: "hogehoge".to_string(),
            verify_code: "hogehoge12345".to_string(),
        };
        let json_body = serde_json::to_string(&auth_request).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/confirm")
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let app = app(Arc::new(mock_service)).await;
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "Validate Error")
    }
}
