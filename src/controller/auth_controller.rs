use std::{error::Error, sync::Arc};

use axum::{http::StatusCode, response::IntoResponse, Extension, Json};

use crate::{application::auth::auth_service::AuthService, domain::entity::auth_user::AuthUser};

pub async fn signin(
    Extension(module): Extension<Arc<dyn AuthService>>,
    Json(payload): Json<AuthUser>,
) -> impl IntoResponse {
    let unko = module
        .auth_by_cognito(payload)
        .await
        .map(|token| (StatusCode::OK, Json(token)).into_response())
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()));
    unko
}
