use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

mod auth;
mod deliveries;
mod delivery_tools;
mod endpoints;
mod events;
mod health;
mod metrics;
mod tenants;
mod timeline;

pub fn router(state: AppState) -> Router<()> {
    let admin = Router::<AppState>::new()
        .merge(tenants::routes())
        .route("/metrics", get(metrics::get_metrics))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ));

    let tenant = Router::<AppState>::new()
        .merge(events::routes())
        .merge(endpoints::routes())
        .merge(deliveries::routes())
        .route("/deliveries/:id/timeline", get(timeline::get_timeline))
        .route(
            "/deliveries/:id/curl",
            get(delivery_tools::get_delivery_curl),
        )
        .route(
            "/deliveries/:id/replay",
            post(delivery_tools::replay_delivery),
        );

    Router::new()
        .merge(health::routes())
        .merge(admin)
        .merge(tenant)
        .with_state(state)
}
