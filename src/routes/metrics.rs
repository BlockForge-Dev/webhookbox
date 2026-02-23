use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::state::AppState;

pub async fn get_metrics(State(state): State<AppState>) -> Response {
    let events_total = match sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM events")
        .fetch_one(&state.pool)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=%e, "failed to collect metrics: events_total");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to collect metrics".to_string(),
            )
                .into_response();
        }
    };

    let deliveries = match sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        r#"
        SELECT
          COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE status = 'pending')::bigint AS pending,
          COUNT(*) FILTER (WHERE status = 'sending')::bigint AS sending,
          COUNT(*) FILTER (WHERE status = 'retrying')::bigint AS retrying,
          COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed
        FROM deliveries
        "#,
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=%e, "failed to collect metrics: deliveries");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to collect metrics".to_string(),
            )
                .into_response();
        }
    };

    let jobs = match sqlx::query_as::<_, (i64, i64, i64, i64)>(
        r#"
        SELECT
          COUNT(*) FILTER (WHERE status = 'queued')::bigint AS queued,
          COUNT(*) FILTER (WHERE status = 'running')::bigint AS running,
          COUNT(*) FILTER (WHERE status = 'done')::bigint AS done,
          COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed
        FROM jobs
        "#,
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error=%e, "failed to collect metrics: jobs");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to collect metrics".to_string(),
            )
                .into_response();
        }
    };

    let dead_letters_total =
        match sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM dead_letters")
            .fetch_one(&state.pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error=%e, "failed to collect metrics: dead_letters");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to collect metrics".to_string(),
                )
                    .into_response();
            }
        };

    let body = format!(
        concat!(
            "# HELP webhookbox_build_info Build information.\n",
            "# TYPE webhookbox_build_info gauge\n",
            "webhookbox_build_info{{version=\"{}\"}} 1\n",
            "# HELP webhookbox_events_total Total events ingested.\n",
            "# TYPE webhookbox_events_total gauge\n",
            "webhookbox_events_total {}\n",
            "# HELP webhookbox_deliveries_total Total deliveries.\n",
            "# TYPE webhookbox_deliveries_total gauge\n",
            "webhookbox_deliveries_total {}\n",
            "# HELP webhookbox_deliveries_status Deliveries by status.\n",
            "# TYPE webhookbox_deliveries_status gauge\n",
            "webhookbox_deliveries_status{{status=\"pending\"}} {}\n",
            "webhookbox_deliveries_status{{status=\"sending\"}} {}\n",
            "webhookbox_deliveries_status{{status=\"retrying\"}} {}\n",
            "webhookbox_deliveries_status{{status=\"failed\"}} {}\n",
            "# HELP webhookbox_jobs_status Jobs by status.\n",
            "# TYPE webhookbox_jobs_status gauge\n",
            "webhookbox_jobs_status{{status=\"queued\"}} {}\n",
            "webhookbox_jobs_status{{status=\"running\"}} {}\n",
            "webhookbox_jobs_status{{status=\"done\"}} {}\n",
            "webhookbox_jobs_status{{status=\"failed\"}} {}\n",
            "# HELP webhookbox_dead_letters_total Dead letter records.\n",
            "# TYPE webhookbox_dead_letters_total gauge\n",
            "webhookbox_dead_letters_total {}\n"
        ),
        env!("CARGO_PKG_VERSION"),
        events_total,
        deliveries.0,
        deliveries.1,
        deliveries.2,
        deliveries.3,
        deliveries.4,
        jobs.0,
        jobs.1,
        jobs.2,
        jobs.3,
        dead_letters_total
    );

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}
