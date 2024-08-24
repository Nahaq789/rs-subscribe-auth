use axum::routing::post;
use axum::Extension;
use axum::Router;
use std::sync::Arc;

use crate::adapter::aws::client::cognito_client::CognitoClient;
use crate::application::auth::auth_service::{AuthService, AuthServiceImpl};
use crate::controller::auth_controller::signin;

pub async fn create_app() {
    let cognito = Arc::new(CognitoClient::from_env().await.unwrap());

    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(cognito));

    let app = Router::new()
        .route("/", post(signin))
        .layer(Extension(auth_service));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
