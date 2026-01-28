use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::<AppState>::new().route("/events", post(create_event))
}

#[derive(Debug, Deserialize)]
struct CreateEventRequest {
    tenant_id: Uuid,
    event_type: String,
    payload: serde_json::Value,
    idempotency_key: String,
}

async fn create_event(
    State(state): State<AppState>,
    Json(req): Json<CreateEventRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.event_type.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "event_type is required" })),
        );
    }

    if req.idempotency_key.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "idempotency_key is required" })),
        );
    }

    let res = sqlx::query!(
        r#"
        INSERT INTO events (id, tenant_id, event_type, payload_json, idempotency_key)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (tenant_id, idempotency_key)
        DO UPDATE SET tenant_id = events.tenant_id
        RETURNING id
        "#,
        Uuid::new_v4(),
        req.tenant_id,
        req.event_type,
        req.payload,
        req.idempotency_key
    )
    .fetch_one(&state.pool)
    .await;

    match res {
        Ok(row) => (
            StatusCode::CREATED,
            Json(json!({ "event_id": row.id, "ok": true })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "failed to create event", "details": e.to_string() })),
        ),
    }
}
