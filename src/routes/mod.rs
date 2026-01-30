use axum::{routing::get, Router};

use crate::state::AppState;

mod deliveries;
mod endpoints;
mod events;
mod health;
mod tenants;
mod timeline;

pub fn router(state: AppState) -> Router<()> {
    Router::new()
        .merge(health::routes())
        .merge(events::routes())
        .merge(tenants::routes())
        .merge(endpoints::routes())
        .merge(deliveries::routes())
        .route("/deliveries/:id/timeline", get(timeline::get_timeline))
        .with_state(state)
}
