use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::auth;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/tenants", post(create_tenant))
        .route("/tenants/:id/api-keys", post(create_tenant_api_key))
}

#[derive(Debug, Deserialize)]
struct CreateTenantRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct CreateTenantApiKeyRequest {
    label: Option<String>,
}

async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<CreateTenantRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "name is required" })),
        );
    }

    let tenant_id = Uuid::new_v4();

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error=%e, "failed to begin tenant transaction");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to begin tx" })),
            );
        }
    };

    let tenant_row = match sqlx::query!(
        r#"
        INSERT INTO tenants (id, name)
        VALUES ($1, $2)
        RETURNING id, name, created_at
        "#,
        tenant_id,
        req.name
    )
    .fetch_one(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!(error=%e, tenant_id=%tenant_id, "failed to create tenant");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": "failed to create tenant" })),
            );
        }
    };

    // default policy row: max_in_flight + max_payload_bytes
    let default_max_in_flight = 10_i32;
    let default_max_payload_bytes = 262_144_i32; // 256KB

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO tenant_policies (tenant_id, max_in_flight, max_payload_bytes)
        VALUES ($1, $2, $3)
        ON CONFLICT (tenant_id) DO NOTHING
        "#,
        tenant_id,
        default_max_in_flight,
        default_max_payload_bytes
    )
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        tracing::error!(error=%e, tenant_id=%tenant_id, "failed to create tenant policy");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": "failed to create tenant policy" })),
        );
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error=%e, tenant_id=%tenant_id, "failed to commit tenant transaction");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": "failed to commit tx" })),
        );
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "tenant": {
                "id": tenant_row.id,
                "name": tenant_row.name,
                "created_at": tenant_row.created_at
            },
            "policy": {
                "max_in_flight": default_max_in_flight,
                "max_payload_bytes": default_max_payload_bytes
            }
        })),
    )
}

async fn create_tenant_api_key(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<CreateTenantApiKeyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let exists = match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)",
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=%e, tenant_id=%tenant_id, "failed to check tenant before creating api key");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to create tenant api key" })),
            );
        }
    };

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": "tenant not found" })),
        );
    }

    let label = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("default");

    let raw_key = format!("tk_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let key_hash = auth::hash_tenant_api_key(&raw_key);
    let key_id = Uuid::new_v4();

    let created_at = match sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        r#"
        INSERT INTO tenant_api_keys (id, tenant_id, label, key_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING created_at
        "#,
    )
    .bind(key_id)
    .bind(tenant_id)
    .bind(label)
    .bind(key_hash)
    .fetch_one(&state.pool)
    .await
    {
        Ok(ts) => ts,
        Err(e) => {
            tracing::error!(error=%e, tenant_id=%tenant_id, "failed to insert tenant api key");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to create tenant api key" })),
            );
        }
    };

    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "api_key": {
                "id": key_id,
                "tenant_id": tenant_id,
                "label": label,
                "key": raw_key,
                "created_at": created_at
            }
        })),
    )
}
