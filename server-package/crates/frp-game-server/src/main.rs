mod app;
mod controller;
mod storage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
