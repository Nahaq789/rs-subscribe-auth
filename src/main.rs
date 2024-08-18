use rs_subscribe_auth::setup::create_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = create_app().await;

    Ok(())
}
