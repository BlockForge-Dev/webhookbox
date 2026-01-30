use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Instant;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use webhookbox::queue::Job;
use webhookbox::{config, db, queue};

type HmacSha256 = Hmac<Sha256>;

enum JobOutcome {
    Done,
    Rescheduled,
}

// -------------------- Explainability v2: error categories --------------------

#[derive(Debug, Clone, Copy)]
enum ErrorCategory {
    DnsFailure,
    TlsFailure,
    Timeout,
    ConnectionRefused,
    Http429,
    Http5xx,
    Http4xx,
}

impl ErrorCategory {
    fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::DnsFailure => "DNS_FAILURE",
            ErrorCategory::TlsFailure => "TLS_FAILURE",
            ErrorCategory::Timeout => "TIMEOUT",
            ErrorCategory::ConnectionRefused => "CONNECTION_REFUSED",
            ErrorCategory::Http429 => "HTTP_429",
            ErrorCategory::Http5xx => "HTTP_5XX",
            ErrorCategory::Http4xx => "HTTP_4XX",
        }
    }

    fn is_retryable(self) -> bool {
        matches!(
            self,
            ErrorCategory::Timeout
                | ErrorCategory::ConnectionRefused
                | ErrorCategory::DnsFailure
                | ErrorCategory::TlsFailure
                | ErrorCategory::Http429
                | ErrorCategory::Http5xx
        )
    }
}

fn classify_http(code: u16) -> ErrorCategory {
    match code {
        429 => ErrorCategory::Http429,
        500..=599 => ErrorCategory::Http5xx,
        400..=499 => ErrorCategory::Http4xx,
        _ => ErrorCategory::Http5xx,
    }
}

fn classify_reqwest(e: &reqwest::Error) -> ErrorCategory {
    if e.is_timeout() {
        return ErrorCategory::Timeout;
    }

    let msg = e.to_string().to_lowercase();

    // DNS-ish
    if msg.contains("dns")
        || msg.contains("name or service not known")
        || msg.contains("failed to lookup address")
        || msg.contains("nodename nor servname provided")
    {
        return ErrorCategory::DnsFailure;
    }

    // TLS-ish
    if msg.contains("tls")
        || msg.contains("certificate")
        || msg.contains("handshake")
        || msg.contains("invalid peer certificate")
        || msg.contains("unknown issuer")
    {
        return ErrorCategory::TlsFailure;
    }

    // Connect / refused
    if e.is_connect() || msg.contains("connection refused") {
        return ErrorCategory::ConnectionRefused;
    }

    ErrorCategory::ConnectionRefused
}

// -------------------- Quarantine policy knobs --------------------

const QUARANTINE_AFTER_CONSEC_FAILS: i32 = 10;
const QUARANTINE_FOR_SECS: i64 = 15 * 60;

// -------------------- Main worker --------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    dotenvy::dotenv().ok();

    let cfg = config::Config::from_env()?;
    let pool = db::connect(&cfg.database_url).await?;
    db::run_migrations(&pool).await?;

    let worker_id = format!("worker-{}", Uuid::new_v4());
    tracing::info!(%worker_id, "worker started");

    let lease_seconds = 30.0;

    loop {
        match queue::lease_one(&pool, &worker_id, lease_seconds).await? {
            Some(job) => {
                tracing::info!(
                    job_id=%job.id,
                    job_type=%job.job_type,
                    attempt=job.attempt,
                    payload=%job.payload_json,
                    "leased job"
                );

                let res: Result<JobOutcome> = match job.job_type.as_str() {
                    "deliver_webhook" => handle_deliver_webhook(&pool, &job).await,
                    other => {
                        tracing::warn!(job_id=%job.id, job_type=%other, "unknown job type, marking done");
                        Ok(JobOutcome::Done)
                    }
                };

                match res {
                    Ok(JobOutcome::Done) => {
                        queue::mark_done(&pool, job.id).await?;
                        tracing::info!(job_id=%job.id, "job done");
                    }
                    Ok(JobOutcome::Rescheduled) => {
                        // IMPORTANT: do NOT mark done; job was re-queued in DB
                        tracing::warn!(job_id=%job.id, "job rescheduled");
                    }
                    Err(e) => {
                        tracing::error!(job_id=%job.id, error=%e, "job failed");
                        queue::mark_failed(&pool, job.id).await?;
                    }
                }
            }
            None => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
        }
    }
}

// -------------------- Deliver webhook job --------------------

async fn handle_deliver_webhook(pool: &sqlx::PgPool, job: &Job) -> Result<JobOutcome> {
    const MAX_ATTEMPTS: i32 = 8;
    const BASE_DELAY_SECS: i64 = 10;
    const CAP_DELAY_SECS: i64 = 15 * 60;

    let delivery_id = job
        .payload_json
        .get("delivery_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing delivery_id in job payload"))?;
    let delivery_id = Uuid::parse_str(delivery_id)?;

    let row = sqlx::query!(
        r#"
        SELECT
          d.id as "delivery_id!",
          d.event_id as "event_id!",
          d.endpoint_id as "endpoint_id!",
          d.attempts_count as "attempts_count!",
          e.url as "endpoint_url!",
          e.enabled as "endpoint_enabled!",
          e.secret as "endpoint_secret!",
          ev.payload_json as "event_payload!",
          ev.tenant_id as "tenant_id!"
        FROM deliveries d
        JOIN endpoints e ON e.id = d.endpoint_id
        JOIN events ev ON ev.id = d.event_id
        WHERE d.id = $1
        "#,
        delivery_id
    )
    .fetch_one(pool)
    .await?;

    // 0) Quarantine check BEFORE max_in_flight reserves a slot
    if let Some(until) = endpoint_quarantine_until(pool, row.endpoint_id).await? {
        log_policy(
            pool,
            row.tenant_id,
            row.delivery_id,
            Some(job.id),
            "deny_reschedule",
            "endpoint_quarantined",
            "ENDPOINT_QUARANTINED",
            serde_json::json!({ "until": until }),
        )
        .await?;

        // reschedule this job for after quarantine
        reschedule_job(pool, job.id, until).await?;

        // keep delivery as retrying so timeline shows “blocked then scheduled”
        sqlx::query!(
            r#"
            UPDATE deliveries
            SET status = 'retrying'::delivery_status,
                next_run_at = $2
            WHERE id = $1
              AND status IN ('pending'::delivery_status, 'retrying'::delivery_status, 'sending'::delivery_status)
            "#,
            row.delivery_id,
            until
        )
        .execute(pool)
        .await?;

        return Ok(JobOutcome::Rescheduled);
    }

    // 1) Tenant max_in_flight policy (this also logs policy_decisions)
    let permit = enforce_max_in_flight(pool, row.tenant_id, row.delivery_id, job.id).await?;
    if matches!(permit, PermitResult::Rescheduled) {
        return Ok(JobOutcome::Rescheduled);
    }

    // 2) attempt metadata
    let attempt_no = row.attempts_count + 1;
    let attempt_id = Uuid::new_v4();
    let ts = chrono::Utc::now().timestamp();

    // disabled endpoint => permanent fail (treat as non-retryable)
    if !row.endpoint_enabled {
        record_attempt(
            pool,
            attempt_id,
            row.delivery_id,
            attempt_no,
            None,
            None,
            Some("endpoint_disabled"),
            Some("HTTP_4XX"),
        )
        .await?;

        finalize_failed_and_dlq(
            pool,
            row.delivery_id,
            job.id,
            dlq_reason_non_retryable(None, Some("HTTP_4XX"), "endpoint_disabled"),
        )
        .await?;

        note_endpoint_failure(pool, row.endpoint_id, Some("HTTP_4XX"), false).await?;
        return Ok(JobOutcome::Done);
    }

    // missing secret => permanent fail (misconfig)
    let secret = row.endpoint_secret.trim();
    if secret.is_empty() {
        record_attempt(
            pool,
            attempt_id,
            row.delivery_id,
            attempt_no,
            None,
            None,
            Some("missing_endpoint_secret"),
            Some("HTTP_4XX"),
        )
        .await?;

        finalize_failed_and_dlq(
            pool,
            row.delivery_id,
            job.id,
            dlq_reason_non_retryable(None, Some("HTTP_4XX"), "missing_endpoint_secret"),
        )
        .await?;

        note_endpoint_failure(pool, row.endpoint_id, Some("HTTP_4XX"), false).await?;
        return Ok(JobOutcome::Done);
    }

    // bytes signed == bytes sent
    let payload_bytes =
        serde_json::to_vec(&row.event_payload).map_err(|e| anyhow!("payload serialize: {e}"))?;

    // signature
    let v1 = sign_v1(
        &row.endpoint_secret,
        ts,
        row.delivery_id,
        attempt_id,
        row.event_id,
        &payload_bytes,
    );
    let signature_header = format!("t={},v1={}", ts, v1);

    tracing::info!(
        delivery_id=%row.delivery_id,
        attempt_id=%attempt_id,
        ts=%ts,
        endpoint=%row.endpoint_url,
        "sending webhook (signed)"
    );

    // send
    let start = Instant::now();
    let resp = reqwest::Client::new()
        .post(&row.endpoint_url)
        .header("Content-Type", "application/json")
        .header("X-Event-Id", row.event_id.to_string())
        .header("X-Delivery-Id", row.delivery_id.to_string())
        .header("X-Attempt-Id", attempt_id.to_string())
        .header("X-Timestamp", ts.to_string())
        .header("X-Signature", signature_header)
        .body(payload_bytes)
        .send()
        .await;

    let latency_ms = start.elapsed().as_millis().min(i32::MAX as u128) as i32;

    // classify result
    let (status_code, error_type, error_category, should_retry) = match resp {
        Ok(r) => {
            let code_u16 = r.status().as_u16();
            let code_i32 = code_u16 as i32;

            if r.status().is_success() {
                (Some(code_i32), None, None, false)
            } else {
                let cat = classify_http(code_u16);
                let et = if code_u16 == 429 {
                    "http_429"
                } else if (500..=599).contains(&code_u16) {
                    "http_5xx"
                } else {
                    "http_4xx"
                };
                let retry = cat.is_retryable();
                (Some(code_i32), Some(et), Some(cat.as_str()), retry)
            }
        }
        Err(e) => {
            let cat = classify_reqwest(&e);
            let et = if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "connect"
            } else {
                "network"
            };
            (None, Some(et), Some(cat.as_str()), cat.is_retryable())
        }
    };

    // record attempt (includes error_category)
    record_attempt(
        pool,
        attempt_id,
        row.delivery_id,
        attempt_no,
        status_code,
        Some(latency_ms),
        error_type,
        error_category,
    )
    .await?;

    // update endpoint health
    let success = matches!(status_code, Some(code) if (200..=299).contains(&code));
    if success {
        note_endpoint_success(pool, row.endpoint_id).await?;
    } else {
        note_endpoint_failure(pool, row.endpoint_id, error_category, should_retry).await?;
    }

    // success
    if success {
        sqlx::query!(
            r#"
            UPDATE deliveries
            SET status = 'delivered'::delivery_status,
                attempts_count = attempts_count + 1,
                next_run_at = NULL
            WHERE id = $1
            "#,
            row.delivery_id
        )
        .execute(pool)
        .await?;
        return Ok(JobOutcome::Done);
    }

    // retry
    if should_retry && attempt_no < MAX_ATTEMPTS {
        // if endpoint got quarantined (threshold reached), schedule at quarantine time
        if let Some(until) = endpoint_quarantine_until(pool, row.endpoint_id).await? {
            log_policy(
                pool,
                row.tenant_id,
                row.delivery_id,
                Some(job.id),
                "deny_reschedule",
                "endpoint_quarantined",
                "ENDPOINT_QUARANTINED",
                serde_json::json!({ "until": until, "after_attempt": attempt_no, "last_error_category": error_category }),
            )
            .await?;

            sqlx::query!(
                r#"
                UPDATE deliveries
                SET status = 'retrying'::delivery_status,
                    attempts_count = attempts_count + 1,
                    next_run_at = $2
                WHERE id = $1
                "#,
                row.delivery_id,
                until
            )
            .execute(pool)
            .await?;

            sqlx::query!(
                r#"
                INSERT INTO jobs (id, job_type, payload_json, run_at, status)
                VALUES ($1, 'deliver_webhook', $2, $3, 'queued')
                "#,
                Uuid::new_v4(),
                serde_json::json!({ "delivery_id": row.delivery_id }),
                until
            )
            .execute(pool)
            .await?;

            return Ok(JobOutcome::Done);
        }

        let delay = compute_backoff_with_jitter(
            row.delivery_id,
            attempt_no,
            BASE_DELAY_SECS,
            CAP_DELAY_SECS,
        );
        let next_time = chrono::Utc::now() + chrono::Duration::seconds(delay);

        sqlx::query!(
            r#"
            UPDATE deliveries
            SET status = 'retrying'::delivery_status,
                attempts_count = attempts_count + 1,
                next_run_at = $2
            WHERE id = $1
            "#,
            row.delivery_id,
            next_time
        )
        .execute(pool)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO jobs (id, job_type, payload_json, run_at, status)
            VALUES ($1, 'deliver_webhook', $2, $3, 'queued')
            "#,
            Uuid::new_v4(),
            serde_json::json!({ "delivery_id": row.delivery_id }),
            next_time
        )
        .execute(pool)
        .await?;

        return Ok(JobOutcome::Done);
    }

    // -------------------- DLQ (reason is now specific + actionable) --------------------
    sqlx::query!(
        r#"
        UPDATE deliveries
        SET status = 'failed'::delivery_status,
            attempts_count = attempts_count + 1,
            next_run_at = NULL
        WHERE id = $1
        "#,
        row.delivery_id
    )
    .execute(pool)
    .await?;

    let dlq_reason = if attempt_no >= MAX_ATTEMPTS {
        dlq_reason_max_attempts(MAX_ATTEMPTS, error_category, status_code)
    } else {
        // non-retryable: e.g. HTTP 401, HTTP 404, etc.
        dlq_reason_non_retryable(
            status_code,
            error_category,
            error_type.unwrap_or("non_retryable"),
        )
    };

    sqlx::query!(
        r#"
        INSERT INTO dead_letters (id, delivery_id, last_job_id, reason)
        VALUES ($1, $2, $3, $4)
        "#,
        Uuid::new_v4(),
        row.delivery_id,
        job.id,
        dlq_reason
    )
    .execute(pool)
    .await?;

    Ok(JobOutcome::Done)
}

// -------------------- Signing --------------------

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

// -------------------- DLQ reason helpers (this is the main “fix”) --------------------

fn dlq_reason_non_retryable(
    status_code: Option<i32>,
    error_category: Option<&str>,
    hint: &str,
) -> String {
    match (status_code, error_category) {
        (Some(code), Some(cat)) => format!("{cat}_NON_RETRYABLE (HTTP {code}) ({hint})"),
        (Some(code), None) => format!("HTTP_NON_RETRYABLE (HTTP {code}) ({hint})"),
        (None, Some(cat)) => format!("{cat}_NON_RETRYABLE ({hint})"),
        (None, None) => format!("NON_RETRYABLE ({hint})"),
    }
}

fn dlq_reason_max_attempts(
    max_attempts: i32,
    error_category: Option<&str>,
    status_code: Option<i32>,
) -> String {
    match (error_category, status_code) {
        (Some(cat), Some(code)) => {
            format!("MAX_ATTEMPTS_EXCEEDED ({max_attempts}) last={cat} (HTTP {code})")
        }
        (Some(cat), None) => format!("MAX_ATTEMPTS_EXCEEDED ({max_attempts}) last={cat}"),
        (None, Some(code)) => format!("MAX_ATTEMPTS_EXCEEDED ({max_attempts}) last=HTTP_{code}"),
        (None, None) => format!("MAX_ATTEMPTS_EXCEEDED ({max_attempts})"),
    }
}

// -------------------- Policy decisions (v2) --------------------

async fn log_policy(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    delivery_id: Uuid,
    job_id: Option<Uuid>,
    decision: &str,
    reason: &str,
    reason_code: &str,
    details_json: serde_json::Value,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO policy_decisions
          (id, tenant_id, delivery_id, job_id, decision, reason, details, reason_code, details_json, created_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, '{}'::jsonb, $7, $8, now())
        "#,
        Uuid::new_v4(),
        tenant_id,
        delivery_id,
        job_id,
        decision,
        reason,
        reason_code,
        details_json
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn reschedule_job(
    pool: &sqlx::PgPool,
    job_id: Uuid,
    run_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE jobs
        SET status = 'queued',
            run_at = $2,
            locked_at = NULL,
            locked_by = NULL,
            lock_expires_at = NULL
        WHERE id = $1
        "#,
        job_id,
        run_at
    )
    .execute(pool)
    .await?;
    Ok(())
}

// -------------------- Max in flight policy --------------------

enum PermitResult {
    Allowed,
    Rescheduled,
}

async fn enforce_max_in_flight(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    delivery_id: Uuid,
    job_id: Uuid,
) -> Result<PermitResult> {
    let mut tx = pool.begin().await?;

    let pol = sqlx::query!(
        r#"
        SELECT max_in_flight
        FROM tenant_policies
        WHERE tenant_id = $1
        FOR UPDATE
        "#,
        tenant_id
    )
    .fetch_optional(&mut *tx)
    .await?;

    let max_in_flight: i32 = if let Some(p) = pol {
        p.max_in_flight
    } else {
        sqlx::query!(
            r#"
            INSERT INTO tenant_policies (tenant_id, max_in_flight, max_payload_bytes)
            VALUES ($1, 10, 262144)
            ON CONFLICT (tenant_id) DO NOTHING
            "#,
            tenant_id
        )
        .execute(&mut *tx)
        .await?;
        10
    };

    let in_flight: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*)::bigint as "count!"
        FROM deliveries d
        JOIN events ev ON ev.id = d.event_id
        WHERE ev.tenant_id = $1
          AND d.status IN ('sending'::delivery_status, 'retrying'::delivery_status)
        "#,
        tenant_id
    )
    .fetch_one(&mut *tx)
    .await?;

    if in_flight >= max_in_flight as i64 {
        // ✅ correct: deny_reschedule
        sqlx::query!(
            r#"
            INSERT INTO policy_decisions
              (id, tenant_id, delivery_id, job_id, decision, reason, details, reason_code, details_json, created_at)
            VALUES
              ($1, $2, $3, $4,
               'deny_reschedule', 'max_in_flight_exceeded', '{}'::jsonb,
               'MAX_IN_FLIGHT_EXCEEDED',
               jsonb_build_object('in_flight', to_jsonb($5::bigint), 'max_in_flight', to_jsonb($6::int)),
               now())
            "#,
            Uuid::new_v4(),
            tenant_id,
            delivery_id,
            job_id,
            in_flight,
            max_in_flight
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            UPDATE jobs
            SET status = 'queued',
                run_at = now() + interval '5 seconds',
                locked_at = NULL,
                locked_by = NULL,
                lock_expires_at = NULL
            WHERE id = $1
            "#,
            job_id
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            UPDATE deliveries
            SET status = 'retrying'::delivery_status,
                next_run_at = now() + interval '5 seconds'
            WHERE id = $1
              AND status IN ('pending'::delivery_status, 'retrying'::delivery_status, 'sending'::delivery_status)
            "#,
            delivery_id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(PermitResult::Rescheduled);
    }

    // reserve slot
    sqlx::query!(
        r#"
        UPDATE deliveries
        SET status = 'sending'::delivery_status
        WHERE id = $1
          AND status IN ('pending'::delivery_status, 'retrying'::delivery_status)
        "#,
        delivery_id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        r#"
        INSERT INTO policy_decisions
          (id, tenant_id, delivery_id, job_id, decision, reason, details, reason_code, details_json, created_at)
        VALUES
          ($1, $2, $3, $4, 'allow', 'within_max_in_flight', '{}'::jsonb,
           'WITHIN_MAX_IN_FLIGHT', '{}'::jsonb, now())
        "#,
        Uuid::new_v4(),
        tenant_id,
        delivery_id,
        job_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(PermitResult::Allowed)
}

// -------------------- Attempts --------------------

async fn record_attempt(
    pool: &sqlx::PgPool,
    attempt_id: Uuid,
    delivery_id: Uuid,
    attempt_no: i32,
    status_code: Option<i32>,
    latency_ms: Option<i32>,
    error_type: Option<&str>,
    error_category: Option<&str>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO attempts
          (id, delivery_id, attempt_no, status_code, latency_ms, error_type, error_category)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7)
        "#,
        attempt_id,
        delivery_id,
        attempt_no,
        status_code,
        latency_ms,
        error_type,
        error_category
    )
    .execute(pool)
    .await?;
    Ok(())
}

// -------------------- Endpoint health / quarantine --------------------
// (Requires endpoint_health table with: endpoint_id (pk), consecutive_failures int,
//  quarantined_until timestamptz null, last_failure_category text null, updated_at timestamptz)

async fn endpoint_quarantine_until(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let row = sqlx::query!(
        r#"
        SELECT quarantined_until
        FROM endpoint_health
        WHERE endpoint_id = $1
        "#,
        endpoint_id
    )
    .fetch_optional(pool)
    .await?;

    if let Some(r) = row {
        if let Some(until) = r.quarantined_until {
            if until > chrono::Utc::now() {
                return Ok(Some(until));
            }
        }
    }
    Ok(None)
}

async fn note_endpoint_success(pool: &sqlx::PgPool, endpoint_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO endpoint_health (endpoint_id, consecutive_failures, quarantined_until, last_failure_category, updated_at)
        VALUES ($1, 0, NULL, NULL, now())
        ON CONFLICT (endpoint_id) DO UPDATE
        SET consecutive_failures = 0,
            quarantined_until = NULL,
            last_failure_category = NULL,
            updated_at = now()
        "#,
        endpoint_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn note_endpoint_failure(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
    error_category: Option<&str>,
    retryable: bool,
) -> Result<()> {
    let now = chrono::Utc::now();

    // increment failures + store last failure category
    let row = sqlx::query!(
        r#"
        INSERT INTO endpoint_health (endpoint_id, consecutive_failures, quarantined_until, last_failure_category, updated_at)
        VALUES ($1, 1, NULL, $2, now())
        ON CONFLICT (endpoint_id) DO UPDATE
        SET consecutive_failures = endpoint_health.consecutive_failures + 1,
            last_failure_category = $2,
            updated_at = now()
        RETURNING consecutive_failures
        "#,
        endpoint_id,
        error_category
    )
    .fetch_one(pool)
    .await?;

    let fails = row.consecutive_failures;

    // quarantine only when threshold reached AND retryable
    if retryable && fails >= QUARANTINE_AFTER_CONSEC_FAILS {
        let until = now + chrono::Duration::seconds(QUARANTINE_FOR_SECS);
        sqlx::query!(
            r#"
            UPDATE endpoint_health
            SET quarantined_until = $2,
                updated_at = now()
            WHERE endpoint_id = $1
            "#,
            endpoint_id,
            until
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}

// -------------------- Small helper: used by misconfig paths --------------------

async fn finalize_failed_and_dlq(
    pool: &sqlx::PgPool,
    delivery_id: Uuid,
    job_id: Uuid,
    dlq_reason: String,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE deliveries
        SET status = 'failed'::delivery_status,
            attempts_count = attempts_count + 1,
            next_run_at = NULL
        WHERE id = $1
        "#,
        delivery_id
    )
    .execute(pool)
    .await?;

    sqlx::query!(
        r#"
        INSERT INTO dead_letters (id, delivery_id, last_job_id, reason)
        VALUES ($1, $2, $3, $4)
        "#,
        Uuid::new_v4(),
        delivery_id,
        job_id,
        dlq_reason
    )
    .execute(pool)
    .await?;

    Ok(())
}

// -------------------- Backoff --------------------

fn compute_backoff_with_jitter(
    delivery_id: Uuid,
    attempt_no: i32,
    base_secs: i64,
    cap_secs: i64,
) -> i64 {
    let exp = (attempt_no - 1).clamp(0, 30) as u32;
    let mut delay = base_secs.saturating_mul(2_i64.saturating_pow(exp));
    if delay > cap_secs {
        delay = cap_secs;
    }

    let bytes = delivery_id.as_bytes();
    let seed = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);

    let max_jitter_ms = std::cmp::min(1000, (delay * 100) as i32).max(0) as u64;
    let jitter_ms = if max_jitter_ms == 0 {
        0
    } else {
        seed % max_jitter_ms
    };

    delay + ((jitter_ms as i64 + 999) / 1000)
}
