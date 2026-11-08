#[tokio::main]
async fn main() -> anyhow::Result<()> {
    authz_tools::serve().await
}
