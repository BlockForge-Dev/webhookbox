use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hex::encode as hex_encode;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::AppState;

pub async fn require_api_key(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = state.api_key.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": "server_auth_not_configured"
            })),
        )
            .into_response();
    };

    let provided = extract_api_key(&req);

    if provided == Some(expected) {
        return next.run(req).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "ok": false, "error": "unauthorized" })),
    )
        .into_response()
}

pub type AuthRejection = (StatusCode, Json<serde_json::Value>);

pub fn hash_tenant_api_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest)
}

pub async fn authorize_tenant(
    state: &AppState,
    headers: &HeaderMap,
    tenant_id: Uuid,
) -> Result<(), AuthRejection> {
    let Some(raw_key) = extract_tenant_api_key(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "missing_tenant_api_key" })),
        ));
    };

    let key_hash = hash_tenant_api_key(raw_key);

    let found_tenant_id =
        sqlx::query_scalar::<_, Uuid>("SELECT tenant_id FROM tenant_api_keys WHERE key_hash = $1")
            .bind(&key_hash)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!(error=%e, "failed to validate tenant api key");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "error": "failed to validate tenant api key" })),
                )
            })?;

    let Some(found_tenant_id) = found_tenant_id else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "invalid_tenant_api_key" })),
        ));
    };

    if found_tenant_id != tenant_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "ok": false, "error": "tenant_access_denied" })),
        ));
    }

    if let Err(e) =
        sqlx::query("UPDATE tenant_api_keys SET last_used_at = now() WHERE key_hash = $1")
            .bind(&key_hash)
            .execute(&state.pool)
            .await
    {
        tracing::warn!(error=%e, tenant_id=%tenant_id, "failed to update tenant api key last_used_at");
    }

    Ok(())
}

fn extract_api_key(req: &Request<Body>) -> Option<&str> {
    if let Some(v) = req.headers().get("x-api-key").and_then(|h| h.to_str().ok()) {
        let key = v.trim();
        if !key.is_empty() {
            return Some(key);
        }
    }

    req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_bearer_token)
}

fn extract_tenant_api_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers
        .get("x-tenant-api-key")
        .and_then(|h| h.to_str().ok())
    {
        let key = v.trim();
        if !key.is_empty() {
            return Some(key);
        }
    }

    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_bearer_token)
}

fn parse_bearer_token(value: &str) -> Option<&str> {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}
