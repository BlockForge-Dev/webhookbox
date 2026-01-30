use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{patch, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/endpoints", post(create_endpoint).get(list_endpoints))
        .route("/endpoints/:id", patch(update_endpoint))
}

#[derive(Debug, Deserialize)]
struct CreateEndpointRequest {
    tenant_id: Uuid,
    url: String,
    secret: String,
    enabled: Option<bool>,
}

async fn create_endpoint(
    State(state): State<AppState>,
    Json(req): Json<CreateEndpointRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "url is required" })),
        );
    }
    if req.secret.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "secret is required" })),
        );
    }

    let id = Uuid::new_v4();
    let enabled = req.enabled.unwrap_or(true);

    let res = sqlx::query!(
        r#"
        INSERT INTO endpoints (id, tenant_id, url, secret, enabled)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, tenant_id, url, enabled, created_at
        "#,
        id,
        req.tenant_id,
        req.url,
        req.secret,
        enabled
    )
    .fetch_one(&state.pool)
    .await;

    match res {
        Ok(row) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "endpoint": {
                    "id": row.id,
                    "tenant_id": row.tenant_id,
                    "url": row.url,
                    "enabled": row.enabled,
                    "created_at": row.created_at
                }
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "failed to create endpoint", "details": e.to_string() })),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct ListEndpointsQuery {
    tenant_id: Uuid,
}

async fn list_endpoints(
    State(state): State<AppState>,
    Query(q): Query<ListEndpointsQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let res = sqlx::query!(
        r#"
        SELECT id, tenant_id, url, enabled, created_at
        FROM endpoints
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        "#,
        q.tenant_id
    )
    .fetch_all(&state.pool)
    .await;

    match res {
        Ok(rows) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "endpoints": rows.into_iter().map(|r| json!({
                    "id": r.id,
                    "tenant_id": r.tenant_id,
                    "url": r.url,
                    "enabled": r.enabled,
                    "created_at": r.created_at
                })).collect::<Vec<_>>()
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "failed to list endpoints", "details": e.to_string() })),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct UpdateEndpointRequest {
    enabled: bool,
}

async fn update_endpoint(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateEndpointRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let res = sqlx::query!(
        r#"
        UPDATE endpoints
        SET enabled = $1
        WHERE id = $2
        RETURNING id, tenant_id, url, enabled, created_at
        "#,
        req.enabled,
        id
    )
    .fetch_optional(&state.pool)
    .await;

    match res {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "endpoint": {
                    "id": row.id,
                    "tenant_id": row.tenant_id,
                    "url": row.url,
                    "enabled": row.enabled,
                    "created_at": row.created_at
                }
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "endpoint not found" })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "failed to update endpoint", "details": e.to_string() })),
        ),
    }
}
