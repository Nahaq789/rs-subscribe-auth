use axum::routing::post;
use axum::Extension;
use axum::Router;
use std::sync::Arc;

use crate::adapter::aws::client::cognito_client::CognitoClient;
use crate::presentation::controller::auth_controller::signup;
use crate::{
    application::auth::auth_service::{AuthService, AuthServiceImpl},
    presentation::controller::auth_controller::signin,
};

pub async fn create_app() {
    let cognito = Arc::new(CognitoClient::from_env().await.unwrap());

    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(cognito));

    let app = Router::new()
        .route("/signin", post(signin))
        .route("/signup", post(signup))
        .layer(Extension(auth_service));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
