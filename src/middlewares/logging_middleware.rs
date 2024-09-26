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
                    println!("k: {}", k);
                    println!("v: {}", v);
                    match v {
                        Value::Array(arr) => {
                            println!("hello");
                            for (i, mut item) in arr.iter().enumerate() {
                                item = &Value::String(mask.to_string());
                            }
                            println!("arr: {:?}", arr);
                        }
                        Value::Object(obj) => {}
                        _ => ()
                    }
                    *v = Value::String(mask.to_string());
                } else {
                    // println!("v: {}", v);
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
    use serde_json::json;

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

    #[test]
    fn test_secret_value_has__nest_secret() {
        let mut value = json!({
            "user": {
                "email": "hoge@email.com",
                "password": "hogehoge",
                "verify_code": "123456"
            },
            "secret": {
                "password": [
                    "hogehoge",
                    "hogehoge",
                    "hogehoge",
                    "hogehoge",
                    "hogehoge",
                ]
            }
        });
        println!("{}", value);
        let result = secret_value(&mut value);
        println!("{}", result)

        // assert_eq!(result["email"], "hoge@email.com");
        // assert_eq!(result["password"], "*********");
        // assert_eq!(result["verify_code"], "*********")
    }
}
