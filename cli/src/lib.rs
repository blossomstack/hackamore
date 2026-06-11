//! halter CLI support library, shared by the `halter` (server) and `halter-agent`
//! (consumer) binaries. The server config lives in [`config`]; the consumer-side
//! provision fetch + native config writers live in [`agent`].

pub mod agent;
pub mod config;
