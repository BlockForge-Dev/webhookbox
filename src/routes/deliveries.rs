use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde_json::json;
use uuid::Uuid;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::<AppState>::new().route("/events/:id/deliveries", get(list_deliveries_for_event))
}

async fn list_deliveries_for_event(
    State(state): State<AppState>,
    Path(event_id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let rows = match sqlx::query!(
        r#"
        SELECT d.id, d.event_id, d.endpoint_id, d.status::text as status,
               d.attempts_count, d.next_run_at, d.created_at,
               e.url as endpoint_url, e.enabled as endpoint_enabled
        FROM deliveries d
        JOIN endpoints e ON e.id = d.endpoint_id
        WHERE d.event_id = $1
        ORDER BY d.created_at ASC
        "#,
        event_id
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "failed to fetch deliveries", "details": e.to_string() })),
            )
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "event_id": event_id,
            "deliveries": rows.into_iter().map(|r| json!({
                "id": r.id,
                "event_id": r.event_id,
                "endpoint_id": r.endpoint_id,
                "endpoint_url": r.endpoint_url,
                "endpoint_enabled": r.endpoint_enabled,
                "status": r.status,
                "attempts_count": r.attempts_count,
                "next_run_at": r.next_run_at,
                "created_at": r.created_at
            })).collect::<Vec<_>>()
        })),
    )
}
