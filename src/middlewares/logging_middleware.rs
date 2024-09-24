use axum::body::{to_bytes, Body, Bytes};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::Request;
use http::StatusCode;
use serde_json::Value;

pub async fn logging_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    tracing::info!("Start request: {} {}", method, path);
    tracing::info!("{:?}", req.body());

    let response = next.run(req).await;
    let (parts, body) = response.into_parts();

    let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
    let json = process_response(&bytes).await.unwrap_or_default();

    match parts.status {
        StatusCode::OK => tracing::info!("End request: {:?}", json),
        _ => tracing::error!("End request: {:?}", json),
    }

    Response::from_parts(parts, Body::from(bytes))
}

async fn process_response(bytes: &Bytes) -> Result<Value, Box<dyn std::error::Error>> {
    let body_string = String::from_utf8(bytes.to_vec())?;
    let json: Value = serde_json::from_str(&body_string)?;
    Ok(json)
}
