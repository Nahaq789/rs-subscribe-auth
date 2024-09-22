use crate::modules::module::AppState;
use crate::presentation::controller::auth_controller::confirm_code;
use crate::presentation::controller::auth_controller::signin;
use crate::presentation::controller::auth_controller::signup;
use axum::routing::post;
use axum::Extension;
use axum::Router;

/// Creates and configures the main application, setting up routes, services, and the HTTP server.
///
/// This function performs the following key tasks:
/// 1. Initializes the AWS Cognito client for authentication services.
/// 2. Sets up the authentication service.
/// 3. Configures the application routes.
/// 4. Starts the HTTP server.
///
/// # Authentication Setup
///
/// The function initializes an AWS Cognito client using environment variables. This client
/// is then used to create an instance of `AuthServiceImpl`, which implements the `AuthService` trait.
/// The authentication service is wrapped in an `Arc` to allow safe sharing across multiple threads.
///
/// # Routing Configuration
///
/// Two routes are set up for authentication:
/// - `/api/v1/auth/signin`: Handles user sign-in requests.
/// - `/api/v1/auth/signup`: Handles user sign-up requests.
///
/// Both routes use POST methods and are mapped to their respective handler functions
/// (`signin` and `signup`) from the `auth_controller` modules.
///
/// # Middleware
///
/// The `Extension` layer is used to inject the `AuthService` into the request handling pipeline.
/// This allows the authentication service to be accessed by route handlers.
///
/// # Server Configuration
///
/// The server is configured to listen on all interfaces (0.0.0.0) on port 8080.
/// It uses Tokio's asynchronous `TcpListener` for handling incoming connections.
///
/// # Error Handling
///
/// This function uses `unwrap()` in several places, which means it will panic if:
/// - The Cognito client fails to initialize from environment variables.
/// - The TCP listener fails to bind to the specified address and port.
/// - The server encounters an error while running.
///
/// In a production environment, you might want to replace these `unwrap()` calls with
/// proper error handling to gracefully handle startup failures.
///
/// # Asynchronous Execution
///
/// This function is asynchronous and should be run within a Tokio runtime, typically
/// called from the `main` function decorated with `#[tokio::main]`.
pub async fn create_app() {
    // Set up DI
    let app_state = AppState::new().await;

    let app = create_router(app_state).await;

    // Create a TCP listener and start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/api/v1/auth/signin", post(signin))
        .route("/api/v1/auth/signup", post(signup))
        .route("/api/v1/auth/confirm", post(confirm_code))
        .layer(Extension(app_state.auth_service))
}

#[cfg(test)]
mod tests {
    use crate::modules::module::AppState;
    use crate::setup::create_router;
    use axum_test::TestServer;
    use http::StatusCode;
    use hyper::{Body, Client, Request};

    #[tokio::test]
    async fn test_app_routes() {
        let app_state = AppState::new().await;
        let app = create_router(app_state).await;
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/api/v1/auth/signin")
            .add_header("Content-Type", "application/json")
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

        let response = server
            .post("/api/v1/auth/signup")
            .add_header("Content-Type", "application/json")
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

        let response = server
            .post("/api/v1/auth/confirm")
            .add_header("Content-Type", "application/json")
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn test_create_app() {
        let app_state = AppState::new().await;
        let app = create_router(app_state).await;

        let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let client = Client::new();
        let req = Request::builder()
            .method("POST")
            .header("Content-Type", "application/json")
            .uri(format!("http://{}/api/v1/auth/signin", addr))
            .body(Body::empty()).unwrap();
        let res = client.request(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST.as_u16());

        let req = Request::builder()
            .method("POST")
            .header("Content-Type", "application/json")
            .uri(format!("http://{}/api/v1/auth/signup", addr))
            .body(Body::empty()).unwrap();
        let res = client.request(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST.as_u16());

        let req = Request::builder()
            .method("POST")
            .header("Content-Type", "application/json")
            .uri(format!("http://{}/api/v1/auth/confirm", addr))
            .body(Body::empty()).unwrap();
        let res = client.request(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST.as_u16());
        server.abort();
    }
}
