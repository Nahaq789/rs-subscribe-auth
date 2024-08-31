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
/// (`signin` and `signup`) from the `auth_controller` module.
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
    // Initialize the Cognito client from environment variables
    let cognito = Arc::new(CognitoClient::from_env().await.unwrap());

    // Create the authentication service
    let auth_service: Arc<dyn AuthService> = Arc::new(AuthServiceImpl::new(cognito));

    // Set up the application routes and inject the auth service
    let app = Router::new()
        .route("/api/v1/auth/signin", post(signin))
        .route("/api/v1/auth/signup", post(signup))
        .layer(Extension(auth_service));

    // Create a TCP listener and start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
