use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::<AppState>::new().route("/tenants", post(create_tenant))
}

#[derive(Debug, Deserialize)]
struct CreateTenantRequest {
    name: String,
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "error": "failed to begin tx", "details": e.to_string() }),
                ),
            )
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
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": "failed to create tenant", "details": e.to_string() }),
                ),
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "error": "failed to create tenant policy", "details": e.to_string() }),
            ),
        );
    }

    if let Err(e) = tx.commit().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": "failed to commit tx", "details": e.to_string() })),
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
