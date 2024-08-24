use anyhow::Result;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Extension;
use axum::{routing::get, Router};
use dotenv::from_filename;
use std::env;
use std::sync::Arc;

use crate::application::auth::auth_service::{AuthService, AuthServiceImpl};
use crate::controller::auth_controller::signin;

pub async fn create_app() {
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new());
    let app = Router::new()
        .route("/", post(signin))
        .layer(Extension(auth_service));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// async fn root() -> Result<impl IntoResponse, StatusCode> {
//     let env_file = get_env_file_name();
//     from_filename(env_file).expect("env file don't open");
//     let user_pool_id = env::var("AWS_USER_POOL_ID");

//     user_pool_id.map(|id| id.into_response()).map_err(|_| {
//         eprintln!("AWS_USER_POOL_ID not found in environment variables");
//         StatusCode::INTERNAL_SERVER_ERROR
//     })
// }

// fn get_env_file_name() -> String {
//     match cfg!(debug_assertions) {
//         true => ".env.dev".to_string(),
//         false => ".env_prod".to_string(),
//     }
// }
