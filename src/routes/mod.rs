use axum::Router;

use crate::state::AppState;

mod events;
mod health;

pub fn router(state: AppState) -> Router {
    Router::<AppState>::new()
        .merge(health::routes())
        .merge(events::routes())
        .with_state(state)
}
