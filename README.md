# WebhookBox

WebhookBox is a Postgres-first webhook delivery service built in Rust.

It gives you:
- Durable event ingest with idempotency
- Fan-out deliveries to tenant endpoints
- Worker retries, backoff, and DLQ
- Delivery explainability (timeline + replay + curl)
- Tenant-scoped API keys for data-plane access
- Basic Prometheus-style metrics

## Stack

- Rust
- Axum
- SQLx + Postgres
- Tokio
- Tracing

## Local Setup

### 1) Start Postgres

```bash
docker compose up -d
```

### 2) Configure environment

Create `.env` in project root:

```env
DATABASE_URL=postgres://webhookbox:webhookbox@localhost:5432/webhookbox
HOST=127.0.0.1
PORT=3000
API_KEY=change-me-admin-key
SECRETS_KEY=change-me-secrets-key
RUST_LOG=info
```

`API_KEY` protects admin routes.
`SECRETS_KEY` encrypts endpoint secrets at rest.

### 3) Run migrations

```bash
sqlx migrate run
```

### 4) Run API + worker

```bash
cargo run
```

In a second terminal:

```bash
cargo run --bin worker
```

## Auth Model

- Admin routes (require `x-api-key`):
  - `POST /tenants`
  - `POST /tenants/:id/api-keys`
  - `GET /metrics`
- Tenant data routes (require `x-tenant-api-key`):
  - `POST /events`
  - `POST/GET/PATCH /endpoints`
  - `GET /events/:id/deliveries`
  - `GET /deliveries/:id/timeline`
  - `GET /deliveries/:id/curl`
  - `POST /deliveries/:id/replay`

## Demo Flow

### Create tenant

```bash
curl -s -X POST http://127.0.0.1:3000/tenants \
  -H "x-api-key: change-me-admin-key" \
  -H "content-type: application/json" \
  -d '{"name":"demo-tenant"}'
```

Save `tenant.id` from the response.

### Create tenant API key

```bash
curl -s -X POST http://127.0.0.1:3000/tenants/<TENANT_ID>/api-keys \
  -H "x-api-key: change-me-admin-key" \
  -H "content-type: application/json" \
  -d '{"label":"demo"}'
```

Save `api_key.key` from the response (returned once).

### Register endpoint

```bash
curl -s -X POST http://127.0.0.1:3000/endpoints \
  -H "x-tenant-api-key: <TENANT_API_KEY>" \
  -H "content-type: application/json" \
  -d '{
    "tenant_id":"<TENANT_ID>",
    "url":"https://example.com/webhook",
    "secret":"super-secret"
  }'
```

### Ingest event

```bash
curl -s -X POST http://127.0.0.1:3000/events \
  -H "x-tenant-api-key: <TENANT_API_KEY>" \
  -H "content-type: application/json" \
  -d '{
    "tenant_id":"<TENANT_ID>",
    "event_type":"user.created",
    "payload":{"user_id":123},
    "idempotency_key":"demo-123"
  }'
```

### Inspect timeline and curl

```bash
curl -s "http://127.0.0.1:3000/events/<EVENT_ID>/deliveries" \
  -H "x-tenant-api-key: <TENANT_API_KEY>"
```

```bash
curl -s "http://127.0.0.1:3000/deliveries/<DELIVERY_ID>/timeline" \
  -H "x-tenant-api-key: <TENANT_API_KEY>"
```

```bash
curl -s "http://127.0.0.1:3000/deliveries/<DELIVERY_ID>/curl" \
  -H "x-tenant-api-key: <TENANT_API_KEY>"
```

## Observability

### Metrics endpoint

`GET /metrics` returns Prometheus-style text metrics (admin key required).

```bash
curl -s http://127.0.0.1:3000/metrics \
  -H "x-api-key: change-me-admin-key"
```

Example metrics:
- `webhookbox_events_total`
- `webhookbox_deliveries_status{status="retrying"}`
- `webhookbox_jobs_status{status="queued"}`
- `webhookbox_dead_letters_total`

### Dashboard starter panels

Use these as initial Prometheus/Grafana panels:
- `webhookbox_events_total`
- `webhookbox_deliveries_status{status="pending"}`
- `webhookbox_deliveries_status{status="retrying"}`
- `webhookbox_jobs_status{status="running"}`
- `webhookbox_dead_letters_total`

### Useful log filters

- Failed jobs:
  - message contains `job failed`
- Delivery attempts:
  - message contains `sending webhook`
- Tenant auth failures:
  - response error equals `invalid_tenant_api_key` or `tenant_access_denied`

## Testing

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Integration tests use `TEST_DATABASE_URL` (or `DATABASE_URL` fallback).

## License

TBD
