//! Almena Network node.
//!
//! For now this is only the service skeleton: configuration, logging and an
//! HTTP server with health endpoints. DIDComm v2.1 support will be added on
//! top of this router.

pub mod config;
pub mod routes;

pub use config::Config;
pub use routes::router;
