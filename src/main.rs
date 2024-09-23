use rs_subscribe_auth::setup::create_app;
use std::env;
use tracing::{event, Level};

/// The main entry point for the rs_subscribe_auth application.
///
/// This function performs the following tasks:
/// 1. Sets up the logging environment.
/// 2. Initializes the application by calling `create_app()`.
/// 3. Handles any errors that might occur during the setup process.
///
/// # Logging
///
/// The function sets the `RUST_LOG` environment variable to "debug", which enables
/// debug-level logging for the application. This is useful for development and
/// troubleshooting purposes.
///
/// # Application Initialization
///
/// The `create_app()` function is called to set up the application. This likely
/// includes tasks such as:
/// - Configuring the web server
/// - Setting up database connections
/// - Initializing authentication services
/// - Registering routes and middleware
///
/// # Error Handling
///
/// The function uses `anyhow::Result` for error handling, which allows for
/// flexible error management. Any errors occurring during the setup process
/// will be propagated up and can be handled by the runtime.
///
/// # Tokio Runtime
///
/// This function is marked with `#[tokio::main]`, which means it's running
/// inside the Tokio asynchronous runtime. This allows for efficient handling
/// of asynchronous operations throughout the application.
///
/// # Returns
///
/// Returns `Ok(())` if the application starts successfully, or an error
/// if something goes wrong during the setup process.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set the log level to debug
    env::set_var("RUST_LOG", "debug");

    // Initialize the logger
    env_logger::init();

    // Log the application start
    event!(Level::INFO, "Application Started");

    // Create and initialize the application
    let _ = create_app().await;

    // If we've reached this point, the application has started successfully
    Ok(())
}
