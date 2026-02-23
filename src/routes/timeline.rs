use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::auth;
use crate::state::AppState;

#[derive(Serialize)]
struct TimelineResponse {
    ok: bool,
    delivery: DeliveryInfo,
    attempts: Vec<AttemptInfo>,
    policy: Vec<PolicyInfo>,
    timeline: Vec<TimelineEntry>,
    next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    summary: String,
    dlq: Option<DlqInfo>,
}

#[derive(Serialize)]
struct DeliveryInfo {
    id: Uuid,
    status: String,
    attempts_count: i32,
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    endpoint_id: Uuid,
    endpoint_url: String,
    endpoint_enabled: bool,
    event_id: Uuid,
    event_type: String,
}

#[derive(Serialize)]
struct AttemptInfo {
    attempt_no: i32,
    status_code: Option<i32>,
    latency_ms: Option<i32>,
    error_type: Option<String>,
    error_category: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    reason: String,
    next_action: String,
}

#[derive(Serialize)]
struct PolicyInfo {
    decision: String,
    reason_code: String,
    details_json: Value,
    created_at: chrono::DateTime<chrono::Utc>,
    next_action: String,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum TimelineEntry {
    Attempt {
        created_at: chrono::DateTime<chrono::Utc>,
        message: String,
        next_action: String,
        attempt_no: i32,
        status_code: Option<i32>,
        error_category: Option<String>,
    },
    Policy {
        created_at: chrono::DateTime<chrono::Utc>,
        message: String,
        next_action: String,
        decision: String,
        reason_code: String,
    },
    Dlq {
        created_at: chrono::DateTime<chrono::Utc>,
        message: String,
        next_action: String,
    },
}

#[derive(Serialize)]
struct DlqInfo {
    reason: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn get_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(delivery_id): Path<Uuid>,
) -> (StatusCode, Json<Value>) {
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
            tracing::error!(error=%e, delivery_id=%delivery_id, "failed to load delivery tenant");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load timeline" })),
            );
        }
    };

    if let Err(rejection) = auth::authorize_tenant(&state, &headers, tenant_id).await {
        return rejection;
    }

    // 1) delivery + endpoint + event
    let d = match sqlx::query!(
        r#"
        SELECT
          d.id,
          d.status::text as "status!",
          d.attempts_count,
          d.next_run_at,
          d.endpoint_id,
          e.url as "endpoint_url!",
          e.enabled as "endpoint_enabled!",
          d.event_id,
          ev.event_type as "event_type!"
        FROM deliveries d
        JOIN endpoints e ON e.id = d.endpoint_id
        JOIN events ev ON ev.id = d.event_id
        WHERE d.id = $1
        "#,
        delivery_id
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "error": "delivery not found" })),
            )
        }
    };

    let status = d.status.clone();

    // 2) attempts
    let attempts_rows = match sqlx::query!(
        r#"
        SELECT attempt_no, status_code, latency_ms, error_type, error_category, created_at
        FROM attempts
        WHERE delivery_id = $1
        ORDER BY attempt_no ASC
        "#,
        delivery_id
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%delivery_id, "failed to load attempts");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load attempts" })),
            );
        }
    };

    let attempts: Vec<AttemptInfo> = attempts_rows
        .into_iter()
        .map(|a| {
            let reason = reason_text(
                a.status_code,
                a.error_type.as_deref(),
                a.error_category.as_deref(),
            );
            let next_action = next_action_for_attempt(
                &status,
                a.status_code,
                a.error_category.as_deref(),
                d.next_run_at,
            );

            AttemptInfo {
                attempt_no: a.attempt_no,
                status_code: a.status_code,
                latency_ms: a.latency_ms,
                error_type: a.error_type,
                error_category: a.error_category,
                created_at: a.created_at,
                reason,
                next_action,
            }
        })
        .collect();

    // 3) policy decisions
    let policy_rows = match sqlx::query!(
        r#"
        SELECT decision, reason_code, details_json, created_at
        FROM policy_decisions
        WHERE delivery_id = $1
        ORDER BY created_at ASC
        "#,
        delivery_id
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error=%e, delivery_id=%delivery_id, "failed to load policy decisions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": "failed to load policy decisions" })),
            );
        }
    };

    let policy: Vec<PolicyInfo> = policy_rows
        .into_iter()
        .map(|p| {
            let next_action =
                next_action_for_policy(&p.decision, &p.reason_code, &p.details_json, d.next_run_at);
            PolicyInfo {
                decision: p.decision,
                reason_code: p.reason_code,
                details_json: p.details_json,
                created_at: p.created_at,
                next_action,
            }
        })
        .collect();

    // 4) dlq
    let dlq_row = sqlx::query!(
        r#"
        SELECT reason, created_at
        FROM dead_letters
        WHERE delivery_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        delivery_id
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let dlq = dlq_row.map(|r| DlqInfo {
        reason: r.reason,
        created_at: r.created_at,
    });

    // 5) merged timeline entries (story mode)
    let mut entries: Vec<(chrono::DateTime<chrono::Utc>, TimelineEntry)> = Vec::new();

    for a in &attempts {
        entries.push((
            a.created_at,
            TimelineEntry::Attempt {
                created_at: a.created_at,
                message: format!("Attempt {}: {}", a.attempt_no, a.reason),
                next_action: a.next_action.clone(),
                attempt_no: a.attempt_no,
                status_code: a.status_code,
                error_category: a.error_category.clone(),
            },
        ));
    }

    for p in &policy {
        entries.push((
            p.created_at,
            TimelineEntry::Policy {
                created_at: p.created_at,
                message: format!("Policy: {} ({})", p.decision, p.reason_code),
                next_action: p.next_action.clone(),
                decision: p.decision.clone(),
                reason_code: p.reason_code.clone(),
            },
        ));
    }

    if let Some(dlq) = &dlq {
        entries.push((
            dlq.created_at,
            TimelineEntry::Dlq {
                created_at: dlq.created_at,
                message: format!("Quarantined to DLQ: {}", dlq.reason),
                next_action: "manual_fix_suggested".to_string(),
            },
        ));
    }

    entries.sort_by_key(|(t, _)| *t);
    let timeline: Vec<TimelineEntry> = entries.into_iter().map(|(_, e)| e).collect();

    // 6) summary
    let summary = build_summary(&status, d.next_run_at, &attempts, dlq.as_ref(), &policy);

    let resp = TimelineResponse {
        ok: true,
        delivery: DeliveryInfo {
            id: d.id,
            status: status.clone(),
            attempts_count: d.attempts_count,
            next_run_at: d.next_run_at,
            endpoint_id: d.endpoint_id,
            endpoint_url: d.endpoint_url,
            endpoint_enabled: d.endpoint_enabled,
            event_id: d.event_id,
            event_type: d.event_type,
        },
        attempts,
        policy,
        timeline,
        next_retry_at: d.next_run_at,
        summary,
        dlq,
    };

    (StatusCode::OK, Json(json!(resp)))
}

// -------------------- helpers --------------------

fn reason_text(
    status_code: Option<i32>,
    _error_type: Option<&str>,
    error_category: Option<&str>,
) -> String {
    if let Some(cat) = error_category {
        return match (cat, status_code) {
            ("HTTP_4XX", Some(code)) => format!("Client error (HTTP {code}) — not retrying"),
            ("HTTP_5XX", Some(code)) => format!("Server error (HTTP {code}) — will retry"),
            ("HTTP_429", _) => "Rate limited (HTTP 429) — will retry".to_string(),

            ("DNS_FAILURE", _) => "DNS failure — hostname could not be resolved".to_string(),
            ("TLS_FAILURE", _) => "TLS failure — handshake/certificate issue".to_string(),
            ("TIMEOUT", _) => "Timed out — will retry".to_string(),
            ("CONNECTION_REFUSED", _) => "Connection refused — endpoint unreachable".to_string(),

            (other, _) => format!("Failed ({other})"),
        };
    }

    // fallback if category missing
    match status_code {
        Some(code) if (200..=299).contains(&code) => format!("Success (HTTP {code})"),
        Some(code) => format!("HTTP {code}"),
        None => "Failed".to_string(),
    }
}

fn next_action_for_attempt(
    delivery_status: &str,
    status_code: Option<i32>,
    error_category: Option<&str>,
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    if delivery_status == "delivered" {
        return "none".to_string();
    }

    if let Some(code) = status_code {
        if (200..=299).contains(&code) {
            return "none".to_string();
        }
        if (400..=499).contains(&code) && code != 429 {
            return "manual_fix_suggested (check request/signature/endpoint)".to_string();
        }
        if code == 429 || (500..=599).contains(&code) {
            return match next_run_at {
                Some(t) => format!("retry_scheduled_at {t}"),
                None => "retry_scheduled".to_string(),
            };
        }
    }

    if let Some(cat) = error_category {
        return match cat {
            "DNS_FAILURE" => "manual_fix_suggested (check hostname/DNS)".to_string(),
            "TLS_FAILURE" => "manual_fix_suggested (check TLS/certs)".to_string(),
            "CONNECTION_REFUSED" => "manual_fix_suggested (service down/port closed)".to_string(),
            "TIMEOUT" => "retry_scheduled".to_string(),
            "HTTP_5XX" => "retry_scheduled".to_string(),
            "HTTP_429" => "retry_scheduled".to_string(),
            "HTTP_4XX" => "manual_fix_suggested".to_string(),
            _ => "retry_scheduled".to_string(),
        };
    }

    "retry_scheduled".to_string()
}

fn next_action_for_policy(
    decision: &str,
    reason_code: &str,
    details_json: &Value,
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    match (decision, reason_code) {
        ("deny_reschedule", "MAX_IN_FLIGHT_EXCEEDED") => match next_run_at {
            Some(t) => format!("retry_scheduled_at {t}"),
            None => "retry_scheduled".to_string(),
        },
        ("deny_reschedule", "ENDPOINT_QUARANTINED") => {
            // Prefer "until" from details_json if present
            if let Some(until) = details_json.get("until").and_then(|v| v.as_str()) {
                return format!("quarantined_until {until}");
            }
            match next_run_at {
                Some(t) => format!("quarantined_until {t}"),
                None => "quarantined".to_string(),
            }
        }
        ("allow", "WITHIN_MAX_IN_FLIGHT") => "continue".to_string(),
        ("deny", _) => "manual_fix_suggested".to_string(),
        _ => "continue".to_string(),
    }
}

fn build_summary(
    status: &str,
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    attempts: &[AttemptInfo],
    dlq: Option<&DlqInfo>,
    policy: &[PolicyInfo],
) -> String {
    if let Some(dlq) = dlq {
        return format!("Moved to DLQ: {}", dlq.reason);
    }

    let last_attempt = attempts.last().map(|a| a.reason.clone());
    let last_policy = policy
        .last()
        .map(|p| format!("{} ({})", p.decision, p.reason_code));

    match status {
        "delivered" => {
            if let Some(a) = attempts.last() {
                format!("Delivered on attempt {}.", a.attempt_no)
            } else {
                "Delivered.".to_string()
            }
        }
        "retrying" => {
            let mut s = last_attempt.unwrap_or_else(|| "Retrying".to_string());
            if let Some(t) = next_run_at {
                s.push_str(&format!(". Next retry at {t}."));
            } else {
                s.push_str(". Next retry scheduled.");
            }
            if let Some(p) = last_policy {
                s.push_str(&format!(" Policy: {p}."));
            }
            s
        }
        "failed" => {
            let mut s = last_attempt.unwrap_or_else(|| "Failed".to_string());
            s.push_str(". No more retries.");
            if let Some(p) = last_policy {
                s.push_str(&format!(" Policy: {p}."));
            }
            s
        }
        "pending" => "Queued (not attempted yet).".to_string(),
        other => format!("Status: {other}"),
    }
}
