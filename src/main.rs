use std::env;

use rs_subscribe_auth::setup::create_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let _ = create_app().await;

    Ok(())
}
