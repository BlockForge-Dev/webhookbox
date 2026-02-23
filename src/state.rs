use sqlx::PgPool;

use crate::crypto::SecretCipher;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub api_key: Option<String>,
    pub secret_cipher: Option<SecretCipher>,
}
