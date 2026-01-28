use sqlx::PgPool;
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod routes;
mod state;

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
    tracing::info!(?cfg, "config loaded");

    // DB
    let pool: PgPool = db::connect(&cfg.database_url).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("db connected + migrations applied");

    // State + Routes
    let state = state::AppState { pool };
    let app = routes::router(state);

    // Serve
    let addr = cfg.bind_addr();
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
