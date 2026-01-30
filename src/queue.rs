use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Job {
    pub id: Uuid,
    pub job_type: String,
    pub payload_json: Value,
    pub attempt: i32,
}

/// Lease ONE job safely.
///
/// Key idea:
/// - Pick one job that is runnable:
///   - status = queued AND run_at <= now()
///   - OR status = running but lock has expired (worker crashed)
/// - Lock row with `FOR UPDATE SKIP LOCKED`
/// - Update it to running and set lock_expires_at
pub async fn lease_one(pool: &PgPool, worker_id: &str, lease_seconds: f64) -> Result<Option<Job>> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query!(
        r#"
        WITH candidate AS (
          SELECT id
          FROM jobs
          WHERE
            (
              status = 'queued'::job_status
              AND run_at <= now()
            )
            OR
            (
              status = 'running'::job_status
              AND lock_expires_at IS NOT NULL
              AND lock_expires_at < now()
            )
          ORDER BY run_at ASC
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE jobs
        SET
          status = 'running'::job_status,
          locked_by = $1,
          locked_at = now(),
          lock_expires_at = now() + make_interval(secs => $2),
          attempt = attempt + 1
        WHERE id IN (SELECT id FROM candidate)
        RETURNING id, job_type, payload_json, attempt
        "#,
        worker_id,
        lease_seconds
    )
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(row.map(|r| Job {
        id: r.id,
        job_type: r.job_type,
        payload_json: r.payload_json,
        attempt: r.attempt,
    }))
}

pub async fn mark_done(pool: &PgPool, job_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE jobs
        SET status = 'done'::job_status,
            locked_at = NULL,
            locked_by = NULL,
            lock_expires_at = NULL
        WHERE id = $1
        "#,
        job_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_failed(pool: &PgPool, job_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE jobs
        SET status = 'failed'::job_status,
            locked_at = NULL,
            locked_by = NULL,
            lock_expires_at = NULL
        WHERE id = $1
        "#,
        job_id
    )
    .execute(pool)
    .await?;
    Ok(())
}
