use axum::body::{to_bytes, Body, Bytes};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::Request;
use http::StatusCode;
use serde_json::Value;

pub async fn logging_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let (parts, body) = req.into_parts();
    let (mut req_json, bytes) = process_response(body).await.unwrap_or_default();

    tracing::info!("Start request: {} {}", method, path);
    tracing::info!("Send Request Body: {:?}", secret_value(&mut req_json));

    let req = Request::from_parts(parts, Body::from(bytes));
    let response = next.run(req).await;

    let (parts, body) = response.into_parts();

    let (mut json, bytes) = process_response(body).await.unwrap_or_default();

    match parts.status {
        StatusCode::OK => tracing::info!("End request: {:?}", json),
        _ => tracing::error!("End request: {:?}", secret_value(&mut json)),
    }

    Response::from_parts(parts, Body::from(bytes))
}

async fn process_response(body: Body) -> Result<(Value, Bytes), Box<dyn std::error::Error>> {
    let bytes = to_bytes(body, usize::MAX).await?;
    let body_string = String::from_utf8(bytes.to_vec())?;
    let res_json: Value = serde_json::from_str(&body_string)?;
    Ok((res_json, bytes))
}

fn secret_value(json: &mut Value) {
    json["password"] = Value::String("*******".to_string())
}