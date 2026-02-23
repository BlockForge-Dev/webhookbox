use sqlx::PgPool;
use tracing_subscriber::EnvFilter;

use webhookbox::{config, crypto, db, routes, state};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Load .env (local dev)
    dotenvy::dotenv().ok();

    // Config
    let cfg = config::Config::from_env()?;
    tracing::info!(host=%cfg.host, port=cfg.port, "config loaded");
    if cfg.api_key.is_none() {
        tracing::warn!("API_KEY is not set; API routes will reject requests");
    }
    if cfg.secrets_key.is_none() {
        tracing::warn!("SECRETS_KEY is not set; endpoint create/curl routes will reject requests");
    }

    // DB

    let pool: PgPool = db::connect(&cfg.database_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("db connected + migrations applied");

    let secret_cipher = cfg
        .secrets_key
        .as_deref()
        .map(crypto::SecretCipher::from_passphrase)
        .transpose()?;

    // State + Routes
    let state = state::AppState {
        pool,
        api_key: cfg.api_key.clone(),
        secret_cipher,
    };
    let app = routes::router(state);

    // Serve
    let addr = cfg.bind_addr();
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
