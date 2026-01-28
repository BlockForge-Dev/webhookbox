use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // pulls from OS env; .env will be loaded in main
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is missing")?;

        let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        let port: u16 = std::env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .map_err(|e| anyhow!("PORT must be a valid u16: {e}"))?;

        Ok(Self {
            database_url,
            host,
            port,
        })
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
