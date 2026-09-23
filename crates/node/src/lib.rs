//! Almena Network node: a DIDComm Messaging v2.0 mediator.

pub mod config;
pub mod identity;
pub mod mediator;
pub mod oob;
pub mod routes;
pub mod store;
#[cfg(test)]
mod testing;
pub mod transport;

pub use config::Config;
pub use routes::{AppState, router};
