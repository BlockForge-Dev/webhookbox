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
            Json(json!({ "ok": false, "error": "event_type is required" })),
        );
    }
    if req.idempotency_key.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "idempotency_key is required" })),
        );
    }

    // ---- Payload size enforcement ----
    let pol = match sqlx::query!(
        r#"
        SELECT max_payload_bytes
        FROM tenant_policies
        WHERE tenant_id = $1
        "#,
        req.tenant_id
    )
    .fetch_optional(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "error": "failed to load tenant policy", "details": e.to_string() }),
                ),
            )
        }
    };

    let max_payload_bytes: i32 = pol.map(|p| p.max_payload_bytes).unwrap_or(262_144);

    // IMPORTANT: measure bytes of payload JSON only (not whole request)
    let payload_bytes = match serde_json::to_vec(&req.payload) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": "invalid payload json", "details": e.to_string() }),
                ),
            )
        }
    };

    let actual_bytes = payload_bytes.len() as i32;
    if actual_bytes > max_payload_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "ok": false,
                "error": "payload_too_large",
                "max_payload_bytes": max_payload_bytes,
                "actual_bytes": actual_bytes
            })),
        );
    }

    // 1) Insert event (idempotent)
    let event_row = match sqlx::query!(
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
    .await
    {
        Ok(row) => row,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": "failed to create event", "details": e.to_string() }),
                ),
            )
        }
    };

    let event_id = event_row.id;

    // 2) Find enabled endpoints for tenant
    let endpoints = match sqlx::query!(
        r#"
        SELECT id
        FROM endpoints
        WHERE tenant_id = $1 AND enabled = TRUE
        "#,
        req.tenant_id
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": "failed to load endpoints", "details": e.to_string() }),
                ),
            )
        }
    };

    // 3) Create deliveries + enqueue jobs
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "error": "failed to begin transaction", "details": e.to_string() }),
                ),
            )
        }
    };

    let mut created_deliveries = 0usize;
    let mut jobs_enqueued = 0usize;

    for ep in endpoints {
        let delivery_id = Uuid::new_v4();

        let inserted = match sqlx::query!(
            r#"
            INSERT INTO deliveries (id, event_id, endpoint_id, status, attempts_count, next_run_at)
            VALUES ($1, $2, $3, 'pending', 0, now())
            ON CONFLICT (event_id, endpoint_id)
            DO NOTHING
            RETURNING id
            "#,
            delivery_id,
            event_id,
            ep.id
        )
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({ "ok": false, "error": "failed to create delivery", "details": e.to_string() }),
                    ),
                );
            }
        };

        if let Some(row) = inserted {
            created_deliveries += 1;

            let job_id = Uuid::new_v4();
            let payload = json!({ "delivery_id": row.id });

            if let Err(e) = sqlx::query!(
                r#"
                INSERT INTO jobs (id, job_type, payload_json, run_at, status)
                VALUES ($1, 'deliver_webhook', $2, now(), 'queued')
                "#,
                job_id,
                payload
            )
            .execute(&mut *tx)
            .await
            {
                let _ = tx.rollback().await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        json!({ "ok": false, "error": "failed to enqueue job", "details": e.to_string() }),
                    ),
                );
            }

            jobs_enqueued += 1;
        }
    }

    if let Err(e) = tx.commit().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "error": "failed to commit transaction", "details": e.to_string() }),
            ),
        );
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "event_id": event_id,
            "deliveries_created": created_deliveries,
            "jobs_enqueued": jobs_enqueued
        })),
    )
}
