![CI](../../actions/workflows/ci.yml/badge.svg)



# WebhookBox

**WebhookBox** is a Postgres-first, self-hosted webhook delivery system focused on two things:

1) **Never lose events** (durable storage + replayable history)  
2) **Make failures obvious** (clear delivery state + attempts timeline as the project evolves)

This repo is being built in public, milestone-by-milestone.


## Why this exists

If you send webhooks directly from your app, you eventually hit:

- retries that happen in the wrong place
- duplicate deliveries when your app retries
- lost events when a process crashes mid-send
- “it failed” with no visibility into *why*
- noisy retry storms that overload systems (later: tenant safety)

WebhookBox solves this by making Postgres the **source of truth**:
- API writes rows
- workers read rows + write results
- UI/debug tools read rows and explain what happened


## Current Status (Milestone 0–1)

✅ **Service boot + DB wiring**
- Axum server + env-based config
- Postgres connection pool (SQLx)
- SQL migrations (`sqlx migrate run`)
- `/health` endpoint checks DB readiness

✅ **Event ingestion + audit log**
- `POST /events` stores events durably in Postgres
- **Idempotency** enforced by a unique constraint: `(tenant_id, idempotency_key)`
  - safe retries from your app without duplicate events



## Roadmap (high level)

- [ ] Tenants API (`POST /tenants`)
- [ ] Endpoints (register customer URLs + secrets)
- [ ] Deliveries (fan-out per endpoint)
- [ ] Postgres queue (jobs, leasing, scheduling, DLQ)
- [ ] Workers (deliver webhooks, retries + backoff)
- [ ] Attempts + error classification (DNS/TLS/timeout/429/5xx)
- [ ] Explainability (timeline, replay, “copy as curl”)
- [ ] Tenant safety (caps, rate limits, quarantine)

---

## Architecture (data flow)

```text
Your App
  │  POST /events
  ▼
WebhookBox API (Axum)
  │  writes events (idempotent)
  ▼
Postgres (source of truth)
  ├─ tenants
  ├─ events
  ├─ endpoints         (next)
  ├─ deliveries        (next)
  ├─ attempts          (next)
  └─ jobs / DLQ        (next)
````

---

## Tech Stack

* Rust
* Axum
* SQLx (Postgres)
* Tokio
* Tracing

---

## Getting Started (Local Dev)

### 1) Start Postgres

```bash
docker compose up -d
```

### 2) Set env vars

Create a `.env` file in the project root:

```env
DATABASE_URL=postgres://webhookbox:webhookbox@localhost:5432/webhookbox
HOST=127.0.0.1
PORT=3000
RUST_LOG=info
```

> Note: `.env` is ignored by git. Don’t commit secrets.

### 3) Run migrations

```bash
sqlx migrate run
```

### 4) Run the service

```bash
cargo run
```

---

## API

### Health Check

```bash
curl -i http://127.0.0.1:3000/health
```

Response:

```json
{ "ok": true, "db": "ok" }
```

---

### Create Tenant (temporary)

For now you can insert a tenant directly in the DB:

```sql
INSERT INTO tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'demo');
```

---

### Ingest Event

```bash
curl -i -X POST http://127.0.0.1:3000/events \
  -H "content-type: application/json" \
  -d '{
    "tenant_id":"00000000-0000-0000-0000-000000000001",
    "event_type":"user.created",
    "payload":{"user_id":123,"email":"a@b.com"},
    "idempotency_key":"abc-123"
  }'
```

Response:

json
{ "event_id": "<uuid>", "ok": true }


#### Idempotency behavior

Repeat the same request with the same `tenant_id` + `idempotency_key`:

* it will return the **same** `event_id`
* it will not create duplicates



## Contributing / Build in Public

Issues and suggestions are welcome. This project is built milestone-by-milestone with a focus on:

* correctness
* reliability
* observability
* explainability


## License

TBD

```

-

If you want, I can also generate:
- a **shorter README** (more startup-style)
- a **more enterprise README** (with guarantees, non-goals, and SLO wording)
- a **badges section** (CI, rustfmt, clippy) once you add GitHub Actions

