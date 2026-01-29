use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    // uses ./migrations at compile time
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

// enum Gender {
//     male(String),
//     female(String),
// }
// struct nationality {
//     name: String,
//     lg: String,
//     age: u16,
//     gender: Gender,
// }
