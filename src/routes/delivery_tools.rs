use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::net::IpAddr;
use uuid::Uuid;

use super::auth;
use crate::crypto;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct CurlResp {
    ok: bool,
    delivery_id: Uuid,
    endpoint_url: String,
    curl: String,
}

#[derive(Deserialize)]
pub struct ReplayReq {
    // optional override endpoint
    endpoint_id: Option<Uuid>,
    // optional override URL (test replay mode)
    #[serde(default, alias = "target_url")]
    override_url: Option<String>,
    // optional: run immediately or schedule later (seconds)
    delay_seconds: Option<i64>,
}

#[derive(Serialize)]
struct ReplayResp {
    ok: bool,
    source_delivery_id: Uuid,
    new_delivery_id: Uuid,
    job_id: Uuid,
    endpoint_id: Uuid,
    run_at: chrono::DateTime<chrono::Utc>,
}

/// GET /deliveries/:id/curl
use axum::extract::Query;
use std::collections::HashMap;

pub async fn get_delivery_curl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(delivery_id): Path<Uuid>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tenant_id = match sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT ev.tenant_id
        FROM deliveries d
        JOIN events ev ON ev.id = d.event_id
        WHERE d.id = $1
        "#,
    )
    .bind(delivery_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "error": "delivery not found" })),
            );
        }
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%delivery_id, "failed to load delivery tenant for curl");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load delivery" })),
            );
        }
    };

    if let Err(rejection) = auth::authorize_tenant(&state, &headers, tenant_id).await {
        return rejection;
    }

    let row = match sqlx::query!(
        r#"
        SELECT
          d.id as "delivery_id!",
          e.url as "endpoint_url!",
          d.target_url as "delivery_target_url",
          e.secret as "endpoint_secret!",
          ev.id as "event_id!",
          ev.payload_json as "event_payload!"
        FROM deliveries d
        JOIN endpoints e ON e.id = d.endpoint_id
        JOIN events ev ON ev.id = d.event_id
        WHERE d.id = $1
        "#,
        delivery_id
    )
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "error": "delivery not found" })),
            );
        }
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%delivery_id, "failed to load delivery for curl");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load delivery" })),
            );
        }
    };

    // ✅ if ?url= is provided, use it
    let default_url = row
        .delivery_target_url
        .as_deref()
        .unwrap_or(&row.endpoint_url);

    let endpoint_url = q
        .get("url")
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_url.to_string());

    // rest of your code same, but use `endpoint_url` instead of row.endpoint_url
    let ts = chrono::Utc::now().timestamp();
    let attempt_id = Uuid::new_v4();

    let payload_bytes = match serde_json::to_vec(&row.event_payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%delivery_id, "failed to serialize payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "payload serialize failed" })),
            );
        }
    };

    let payload_str =
        serde_json::to_string_pretty(&row.event_payload).unwrap_or_else(|_| "{}".to_string());

    let resolved_secret = if crypto::is_encrypted_secret(&row.endpoint_secret) {
        let Some(cipher) = state.secret_cipher.as_ref() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "ok": false, "error": "server_secrets_not_configured" })),
            );
        };

        match cipher.decrypt(&row.endpoint_secret) {
            Ok(secret) => secret,
            Err(e) => {
                tracing::error!(error=%e, delivery_id=%delivery_id, "failed to decrypt endpoint secret");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "error": "failed to decrypt endpoint secret" })),
                );
            }
        }
    } else {
        row.endpoint_secret.clone()
    };
    let secret = resolved_secret.trim();
    let curl = if secret.is_empty() {
        build_curl_unsigned(
            &endpoint_url,
            row.event_id,
            row.delivery_id,
            attempt_id,
            ts,
            &payload_str,
        )
    } else {
        let v1 = sign_v1(
            secret,
            ts,
            row.delivery_id,
            attempt_id,
            row.event_id,
            &payload_bytes,
        );
        let sig_header = format!("t={},v1={}", ts, v1);

        build_curl_signed(
            &endpoint_url,
            row.event_id,
            row.delivery_id,
            attempt_id,
            ts,
            &sig_header,
            &payload_str,
        )
    };

    let resp = CurlResp {
        ok: true,
        delivery_id: row.delivery_id,
        endpoint_url,
        curl,
    };

    (StatusCode::OK, Json(json!(resp)))
}

/// POST /deliveries/:id/replay
/// Creates a *new* delivery row + enqueues a job (clean audit trail).
pub async fn replay_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(source_delivery_id): Path<Uuid>,
    Json(req): Json<ReplayReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tenant_id = match sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT ev.tenant_id
        FROM deliveries d
        JOIN events ev ON ev.id = d.event_id
        WHERE d.id = $1
        "#,
    )
    .bind(source_delivery_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "error": "delivery not found" })),
            );
        }
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%source_delivery_id, "failed to load source delivery tenant");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load source delivery" })),
            );
        }
    };

    if let Err(rejection) = auth::authorize_tenant(&state, &headers, tenant_id).await {
        return rejection;
    }

    // Load source delivery (to get event_id + original endpoint_id)
    let src = match sqlx::query!(
        r#"
        SELECT id, event_id, endpoint_id
        FROM deliveries
        WHERE id = $1
        "#,
        source_delivery_id
    )
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "error": "delivery not found" })),
            );
        }
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%source_delivery_id, "failed to load source delivery for replay");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load source delivery" })),
            );
        }
    };

    let endpoint_id = req.endpoint_id.unwrap_or(src.endpoint_id);
    let override_url = match req
        .override_url
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => match validate_override_url(raw) {
            Ok(url) => Some(url),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "error": err })),
                );
            }
        },
        None => None,
    };
    let new_delivery_id = Uuid::new_v4();
    let job_id = Uuid::new_v4();

    let delay = req.delay_seconds.unwrap_or(0).max(0);
    let run_at = chrono::Utc::now() + chrono::Duration::seconds(delay);

    // Do it atomically
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%source_delivery_id, "failed to begin replay transaction");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to start replay transaction" })),
            );
        }
    };

    // Insert new delivery record (clean audit)
    // NOTE: adjust columns if your schema differs (created_at default is fine)
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO deliveries (
          id, event_id, endpoint_id, status, attempts_count, next_run_at,
          is_replay, replay_of_delivery_id, target_url
        )
        VALUES ($1, $2, $3, 'pending'::delivery_status, 0, $4, TRUE, $5, $6)
        "#,
        new_delivery_id,
        src.event_id,
        endpoint_id,
        run_at,
        source_delivery_id,
        override_url.as_deref()
    )
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        tracing::error!(error=%e, source_delivery_id=%source_delivery_id, new_delivery_id=%new_delivery_id, "failed to create replay delivery");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": "failed to create replay delivery" })),
        );
    }

    // Enqueue job for new delivery
    let mut payload = serde_json::json!({ "delivery_id": new_delivery_id });
    if let Some(u) = override_url.as_deref() {
        payload["override_url"] = serde_json::Value::String(u.to_string());
    }

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO jobs (id, job_type, payload_json, run_at, status)
        VALUES ($1, 'deliver_webhook', $2, $3, 'queued')
        "#,
        job_id,
        payload,
        run_at
    )
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        tracing::error!(error=%e, source_delivery_id=%source_delivery_id, new_delivery_id=%new_delivery_id, "failed to enqueue replay job");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": "failed to enqueue replay job" })),
        );
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error=%e, source_delivery_id=%source_delivery_id, new_delivery_id=%new_delivery_id, "failed to commit replay transaction");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": "failed to commit replay transaction" })),
        );
    }

    let resp = ReplayResp {
        ok: true,
        source_delivery_id,
        new_delivery_id,
        job_id,
        endpoint_id,
        run_at,
    };

    (StatusCode::OK, Json(json!(resp)))
}

// -------------------- Curl builders --------------------

fn shell_escape_single_quotes(s: &str) -> String {
    // bash-safe single-quote escape: ' -> '"'"'
    s.replace('\'', r#"'\"'\"'"#)
}

fn validate_override_url(raw: &str) -> Result<String, &'static str> {
    let url = reqwest::Url::parse(raw).map_err(|_| "override_url must be a valid absolute URL")?;

    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("override_url must use http or https"),
    }

    let host = url
        .host_str()
        .ok_or("override_url must include a host")?
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".local") {
        return Err("override_url host is not allowed");
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        let blocked = match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_multicast()
            }
        };

        if blocked {
            return Err("override_url IP is not allowed");
        }
    }

    Ok(url.to_string())
}

fn build_curl_unsigned(
    url: &str,
    event_id: Uuid,
    delivery_id: Uuid,
    attempt_id: Uuid,
    ts: i64,
    payload_pretty_json: &str,
) -> String {
    let body = shell_escape_single_quotes(payload_pretty_json);
    format!(
        "curl -i -X POST '{url}' \\\n\
         -H 'Content-Type: application/json' \\\n\
         -H 'X-Event-Id: {event_id}' \\\n\
         -H 'X-Delivery-Id: {delivery_id}' \\\n\
         -H 'X-Attempt-Id: {attempt_id}' \\\n\
         -H 'X-Timestamp: {ts}' \\\n\
         --data-raw '{body}'"
    )
}

fn build_curl_signed(
    url: &str,
    event_id: Uuid,
    delivery_id: Uuid,
    attempt_id: Uuid,
    ts: i64,
    signature_header: &str, // "t=...,v1=..."
    payload_pretty_json: &str,
) -> String {
    let body = shell_escape_single_quotes(payload_pretty_json);
    format!(
        "curl -i -X POST '{url}' \\\n\
         -H 'Content-Type: application/json' \\\n\
         -H 'X-Event-Id: {event_id}' \\\n\
         -H 'X-Delivery-Id: {delivery_id}' \\\n\
         -H 'X-Attempt-Id: {attempt_id}' \\\n\
         -H 'X-Timestamp: {ts}' \\\n\
         -H 'X-Signature: {signature_header}' \\\n\
         --data-raw '{body}'"
    )
}

// -------------------- Signing (same as worker) --------------------

fn sign_v1(
    secret: &str,
    ts: i64,
    delivery_id: Uuid,
    attempt_id: Uuid,
    event_id: Uuid,
    payload: &[u8],
) -> String {
    let mut msg = Vec::with_capacity(128 + payload.len());
    msg.extend_from_slice(ts.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(delivery_id.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(attempt_id.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(event_id.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(payload);

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(&msg);
    hex::encode(mac.finalize().into_bytes())
}
