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
    tracing::info!("Send Request Body: {}", secret_value(&mut req_json));

    let req = Request::from_parts(parts, Body::from(bytes));
    let response = next.run(req).await;

    let (parts, body) = response.into_parts();

    let (mut res_json, bytes) = process_response(body).await.unwrap_or_default();

    match parts.status {
        StatusCode::OK => tracing::info!("End request: {}", res_json),
        _ => tracing::error!("End request: {}", secret_value(&mut res_json)),
    }

    Response::from_parts(parts, Body::from(bytes))
}

async fn process_response(body: Body) -> Result<(Value, Bytes), Box<dyn std::error::Error>> {
    let bytes = to_bytes(body, usize::MAX).await?;
    let body_string = String::from_utf8(bytes.to_vec())?;
    let res_json: Value = serde_json::from_str(&body_string)?;
    Ok((res_json, bytes))
}

fn secret_value(value: &mut Value) -> &mut Value {
    let mask = "*********";
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if k == "password" || k == "verify_code" {
                    match v {
                        Value::Array(arr) => {
                            for item in arr.iter_mut() {
                                *item = Value::String(mask.to_string())
                            }
                        }
                        Value::Object(obj) => {
                            for (_, val) in obj.iter_mut() {
                                *val = Value::String(mask.to_string())
                            }
                        }
                        _ => {
                            *v = Value::String(mask.to_string());
                        }
                    }
                } else {
                    secret_value(v);
                }
            }
        }
        Value::Array(vec) => {
            for v in vec {
                secret_value(v);
            }
        }
        _ => {}
    };
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::post;
    use axum::{middleware, Json, Router};
    use log::Level;
    use rstest::rstest;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tower::ServiceExt;

    #[test]
    fn test_secret_value_has_secret() {
        let mut value = json!({
            "email": "hoge@email.com",
            "password": "hogehoge",
            "verify_code": "123456"
        });
        let result = secret_value(&mut value);

        assert_eq!(result["email"], "hoge@email.com");
        assert_eq!(result["password"], "*********");
        assert_eq!(result["verify_code"], "*********")
    }

    #[rstest]
    #[test]
    #[case::nested_object(
        json!({
            "user": {
                "email": "hoge@email.com",
                "password": "hogehoge",
                "verify_code": "123456"
            }
        }),
        json!({
            "user": {
                "email": "hoge@email.com",
                "password": "*********",
                "verify_code": "*********"
            }
        })
    )]
    #[case::nested_array(
        json!({
            "secret": {
                "password": ["hogehoge", "hogehoge", "hogehoge"],
                "verify_code": ["hogehoge", "hogehoge", "hogehoge"]
            }
        }),
        json!({
            "secret": {
                "password": ["*********", "*********", "*********"],
                "verify_code": ["*********", "*********", "*********"]
            }
        })
    )]
    #[case::object_array(
        json!({
            "password": ["1111", "2222", "3333"]
        }),
        json!({
            "password": ["*********", "*********", "*********"]
        })
    )]
    #[case::top_level_array(
        json!([
            {"password": "secret123"}
        ]),
        json!([
            {"password": "*********"}
        ])
    )]
    #[case::nested_top_level_array(
        json!([
            [{"password": "secret1"}, {"verify_code": "123456"}],
            {"user": {"password": "userpass", "email": "user@example.com"}},
            [
                {"nested": {"password": "nestedpass"}},
                [{"deep": {"verify_code": "deepcode"}}]
            ],
            "not_a_secret",
            42,
            [true, false, {"password": ["multi", "pass"]}]
        ]),
        json!([
            [{"password": "*********"}, {"verify_code": "*********"}],
            {"user": {"password": "*********", "email": "user@example.com"}},
            [
                {"nested": {"password": "*********"}},
                [{"deep": {"verify_code": "*********"}}]
            ],
            "not_a_secret",
            42,
            [true, false, {"password": ["*********", "*********"]}]
        ])
    )]
    fn test_secret_value(#[case] input: serde_json::Value, #[case] expected: serde_json::Value) {
        let mut value = input;
        let result = secret_value(&mut value);

        assert_eq!(result, &expected);
    }

    #[tokio::test]
    async fn test_process_response_success() {
        let json = json!({"fuga": "hoge"});
        let response_body = Body::from(json.to_string());
        let (parts, raw) = process_response(response_body).await.unwrap_or_default();

        assert_eq!(parts, json);
        assert_eq!(raw, Bytes::from(json.to_string()))
    }

    #[tokio::test]
    async fn test_process_response_failed() {
        let json = "{ invalid json }";
        let response_body = Body::from(json);
        let result = process_response(response_body).await;

        assert!(result.is_err())
    }

    #[tokio::test]
    async fn test_process_response_empty() {
        let response_body = Body::empty();
        let result = process_response(response_body).await;

        assert!(result.is_err())
    }

    #[tokio::test]
    async fn test_logging_middleware_success() {
        testing_logger::setup();
        let json = json!({
            "message": "fugafuga"
        });
        let json_body = serde_json::to_string(&json).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::new(json_body))
            .unwrap();
        let router = create_router().await;
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 3);
            for i in 0..captured_logs.len() {
                assert_eq!(captured_logs[i].level, Level::Info);
            }
            assert_eq!(captured_logs[0].body, "Start request: POST /");
            assert_eq!(
                captured_logs[1].body,
                "Send Request Body: {\"message\":\"fugafuga\"}"
            );
            assert_eq!(
                captured_logs[2].body,
                "End request: {\"message\":\"fugafugahogehoge\"}"
            );
        });
    }

    async fn create_router() -> Router {
        Router::new()
            .route("/", post(test_hogehoge_endpoint))
            .layer(middleware::from_fn(logging_middleware))
    }
    #[derive(Deserialize, Serialize)]
    struct TestDto {
        message: String,
    }
    async fn test_hogehoge_endpoint(Json(payload): Json<TestDto>) -> impl IntoResponse {
        let value = json!({
            "message": payload.message + "hogehoge"
        });
        Json(value)
    }
}
