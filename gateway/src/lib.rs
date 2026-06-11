//! halter data plane — the reverse proxy that enforces policy decisions.
//!
//! - [`normalize`] turns an HTTP request into the engine's `Action` (the protocol
//!   adapter; generic by default, with per-service flavors).
//! - [`service`] is the configurable upstream allowlist and Host-based router.
//! - [`core`] is the transport-agnostic decision + enforcement path ([`Gateway`]).
//! - [`server`] is the axum HTTP surface and the streaming forwarder (HTTP + SSE).

pub mod canonicalize;
pub mod core;
pub mod normalize;
pub mod server;
pub mod service;
pub mod sigv4;
pub mod tls;
pub mod upgrade;

pub use core::{ForwardPlan, Gateway, MintError, Outcome, ProxyRequest, Rejection};
pub use server::{ServerState, admin_router, proxy_router, serve};
pub use service::{Catalog, Extract, Flavor, Outbound, Protocol, Service, ServiceRouter};
pub use tls::TlsMaterial;
