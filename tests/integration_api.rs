use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::OnceCell;
use tower::util::ServiceExt;
use uuid::Uuid;

use webhookbox::{crypto::SecretCipher, db, routes, state::AppState};

static MIGRATIONS: OnceCell<()> = OnceCell::const_new();

async fn setup_app() -> Option<(Router, PgPool, String)> {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())?;

    let pool = match db::connect(&db_url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("skipping integration test: failed to connect db: {e}");
            return None;
        }
    };

    MIGRATIONS
        .get_or_init(|| async {
            db::run_migrations(&pool)
                .await
                .expect("failed to run migrations for integration tests");
        })
        .await;

    let api_key = "integration-api-key".to_string();
    let secret_cipher =
        SecretCipher::from_passphrase("integration-secrets-key").expect("valid test key");

    let state = AppState {
        pool: pool.clone(),
        api_key: Some(api_key.clone()),
        secret_cipher: Some(secret_cipher),
    };
    let app = routes::router(state);

    Some((app, pool, api_key))
}

fn uuid_from_json(v: &Value, path: &[&str]) -> Uuid {
    let mut cur = v;
    for key in path {
        cur = &cur[*key];
    }
    let raw = cur.as_str().expect("missing uuid string");
    Uuid::parse_str(raw).expect("invalid uuid")
}

async fn send_json(
    app: &Router,
    method: Method,
    path: &str,
    admin_api_key: Option<&str>,
    tenant_api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(key) = admin_api_key {
        req = req.header("x-api-key", key);
    }
    if let Some(key) = tenant_api_key {
        req = req.header("x-tenant-api-key", key);
    }
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }

    let request = req
        .body(match body {
            Some(v) => Body::from(v.to_string()),
            None => Body::empty(),
        })
        .expect("failed to build request");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("request handling failed");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("failed to read response body");
    let payload = serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| {
        json!({
            "raw": String::from_utf8_lossy(&bytes).to_string()
        })
    });
    (status, payload)
}

async fn create_tenant(app: &Router, admin_api_key: &str) -> Uuid {
    let tenant_name = format!("it-tenant-{}", Uuid::new_v4());
    let (status, tenant_resp) = send_json(
        app,
        Method::POST,
        "/tenants",
        Some(admin_api_key),
        None,
        Some(json!({ "name": tenant_name })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "tenant create failed: {tenant_resp}"
    );
    uuid_from_json(&tenant_resp, &["tenant", "id"])
}

async fn create_tenant_api_key(app: &Router, admin_api_key: &str, tenant_id: Uuid) -> String {
    let (status, key_resp) = send_json(
        app,
        Method::POST,
        &format!("/tenants/{tenant_id}/api-keys"),
        Some(admin_api_key),
        None,
        Some(json!({ "label": "integration" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "tenant api key create failed: {key_resp}"
    );
    key_resp["api_key"]["key"]
        .as_str()
        .expect("missing tenant api key")
        .to_string()
}

async fn seed_delivery(
    app: &Router,
    pool: &PgPool,
    admin_api_key: &str,
) -> (Uuid, String, Uuid, Uuid, Uuid) {
    let tenant_id = create_tenant(app, admin_api_key).await;
    let tenant_api_key = create_tenant_api_key(app, admin_api_key, tenant_id).await;

    let endpoint_secret = "super-secret-value";
    let (status, endpoint_resp) = send_json(
        app,
        Method::POST,
        "/endpoints",
        None,
        Some(&tenant_api_key),
        Some(json!({
            "tenant_id": tenant_id,
            "url": "https://example.com/webhook",
            "secret": endpoint_secret
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "endpoint create failed: {endpoint_resp}"
    );
    let endpoint_id = uuid_from_json(&endpoint_resp, &["endpoint", "id"]);

    let stored_secret: String = sqlx::query_scalar("SELECT secret FROM endpoints WHERE id = $1")
        .bind(endpoint_id)
        .fetch_one(pool)
        .await
        .expect("failed to load stored endpoint secret");
    assert_ne!(stored_secret, endpoint_secret);
    assert!(
        stored_secret.starts_with("enc:v1:"),
        "expected encrypted prefix, got: {stored_secret}"
    );

    let (status, event_resp) = send_json(
        app,
        Method::POST,
        "/events",
        None,
        Some(&tenant_api_key),
        Some(json!({
            "tenant_id": tenant_id,
            "event_type": "user.created",
            "payload": { "user_id": 42 },
            "idempotency_key": format!("it-idem-{}", Uuid::new_v4())
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "event create failed: {event_resp}"
    );
    let event_id = uuid_from_json(&event_resp, &["event_id"]);

    let delivery_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM deliveries WHERE event_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(event_id)
    .fetch_one(pool)
    .await
    .expect("failed to load delivery");

    (
        tenant_id,
        tenant_api_key,
        endpoint_id,
        event_id,
        delivery_id,
    )
}

#[tokio::test]
async fn admin_routes_require_shared_api_key() {
    let Some((app, _pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/tenants",
        None,
        None,
        Some(json!({ "name": format!("it-unauth-{}", Uuid::new_v4()) })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/tenants",
        Some(&admin_api_key),
        None,
        Some(json!({ "name": format!("it-auth-{}", Uuid::new_v4()) })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = send_json(
        &app,
        Method::GET,
        "/metrics",
        Some(&admin_api_key),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tenant_routes_require_tenant_api_key() {
    let Some((app, _pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let tenant_id = create_tenant(&app, &admin_api_key).await;
    let tenant_api_key = create_tenant_api_key(&app, &admin_api_key, tenant_id).await;

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/endpoints",
        None,
        None,
        Some(json!({
            "tenant_id": tenant_id,
            "url": "https://example.com/hook",
            "secret": "abc"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/endpoints",
        None,
        Some(&tenant_api_key),
        Some(json!({
            "tenant_id": tenant_id,
            "url": "https://example.com/hook",
            "secret": "abc"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn endpoint_secret_is_encrypted_and_curl_is_signed() {
    let Some((app, pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let (_tenant_id, tenant_api_key, _endpoint_id, _event_id, delivery_id) =
        seed_delivery(&app, &pool, &admin_api_key).await;

    let (status, curl_resp) = send_json(
        &app,
        Method::GET,
        &format!("/deliveries/{delivery_id}/curl"),
        None,
        Some(&tenant_api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "curl endpoint failed: {curl_resp}");

    let curl = curl_resp["curl"].as_str().expect("missing curl command");
    assert!(
        curl.contains("X-Signature: t="),
        "expected signed curl output: {curl}"
    );
}

#[tokio::test]
async fn replay_rejects_private_override_url() {
    let Some((app, pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let (_tenant_id, tenant_api_key, _endpoint_id, _event_id, delivery_id) =
        seed_delivery(&app, &pool, &admin_api_key).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        &format!("/deliveries/{delivery_id}/replay"),
        None,
        Some(&tenant_api_key),
        Some(json!({ "override_url": "http://127.0.0.1:8080/hook" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unexpected response: {body}"
    );
    assert_eq!(body["error"], "override_url IP is not allowed");
}

#[tokio::test]
async fn tenant_key_cannot_access_other_tenant_data() {
    let Some((app, pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let (_tenant_a, _tenant_a_key, _endpoint_id, _event_id, delivery_id_a) =
        seed_delivery(&app, &pool, &admin_api_key).await;
    let tenant_b = create_tenant(&app, &admin_api_key).await;
    let tenant_b_key = create_tenant_api_key(&app, &admin_api_key, tenant_b).await;

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/deliveries/{delivery_id_a}/timeline"),
        None,
        Some(&tenant_b_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
    assert_eq!(body["error"], "tenant_access_denied");
}

#[tokio::test]
async fn timeline_includes_retry_and_quarantine_story() {
    let Some((app, pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let (tenant_id, tenant_api_key, _endpoint_id, _event_id, delivery_id) =
        seed_delivery(&app, &pool, &admin_api_key).await;

    let next_run = Utc::now() + Duration::seconds(45);
    sqlx::query("UPDATE deliveries SET status = 'retrying', next_run_at = $2 WHERE id = $1")
        .bind(delivery_id)
        .bind(next_run)
        .execute(&pool)
        .await
        .expect("failed to update delivery status to retrying");

    sqlx::query(
        r#"
        INSERT INTO attempts (id, delivery_id, attempt_no, status_code, latency_ms, error_type, error_category)
        VALUES ($1, $2, 1, NULL, 1200, 'timeout', 'TIMEOUT')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(delivery_id)
    .execute(&pool)
    .await
    .expect("failed to insert attempt");

    sqlx::query(
        r#"
        INSERT INTO policy_decisions
          (id, tenant_id, delivery_id, decision, reason, details, reason_code, details_json, created_at)
        VALUES
          ($1, $2, $3, 'deny_reschedule', 'endpoint_quarantined', '{}'::jsonb,
           'ENDPOINT_QUARANTINED', jsonb_build_object('until', to_jsonb($4::timestamptz)), now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(delivery_id)
    .bind(next_run)
    .execute(&pool)
    .await
    .expect("failed to insert policy decision");

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/deliveries/{delivery_id}/timeline"),
        None,
        Some(&tenant_api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

    let summary = body["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("Next retry at"),
        "expected retry summary, got: {summary}"
    );
    assert_eq!(body["policy"][0]["reason_code"], "ENDPOINT_QUARANTINED");
}

#[tokio::test]
async fn timeline_includes_dlq_story() {
    let Some((app, pool, admin_api_key)) = setup_app().await else {
        eprintln!("skipping integration test: set TEST_DATABASE_URL or DATABASE_URL");
        return;
    };

    let (_tenant_id, tenant_api_key, _endpoint_id, _event_id, delivery_id) =
        seed_delivery(&app, &pool, &admin_api_key).await;

    sqlx::query("UPDATE deliveries SET status = 'failed', attempts_count = 1, next_run_at = NULL WHERE id = $1")
        .bind(delivery_id)
        .execute(&pool)
        .await
        .expect("failed to update delivery failed");

    sqlx::query(
        r#"
        INSERT INTO attempts (id, delivery_id, attempt_no, status_code, latency_ms, error_type, error_category)
        VALUES ($1, $2, 1, 404, 50, 'http_4xx', 'HTTP_4XX')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(delivery_id)
    .execute(&pool)
    .await
    .expect("failed to insert failed attempt");

    let dlq_reason = "HTTP_4XX_NON_RETRYABLE (HTTP 404) (http_4xx)";
    sqlx::query(
        "INSERT INTO dead_letters (id, delivery_id, last_job_id, reason) VALUES ($1, $2, NULL, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(delivery_id)
    .bind(dlq_reason)
    .execute(&pool)
    .await
    .expect("failed to insert dead letter");

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/deliveries/{delivery_id}/timeline"),
        None,
        Some(&tenant_api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    assert!(
        body["summary"]
            .as_str()
            .unwrap_or_default()
            .starts_with("Moved to DLQ"),
        "expected dlq summary, got: {}",
        body["summary"]
    );
    assert_eq!(body["dlq"]["reason"], dlq_reason);
}
