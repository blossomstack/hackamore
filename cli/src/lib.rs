//! hackamore CLI support library for the `hackamore` (server) binary. The server config lives
//! in [`config`]; output rendering for the discovery commands in [`render`]. The
//! consumer-side provision fetch + native config writers now live in the standalone
//! `hackamore-agent` crate.

pub mod config;
pub mod k8s;
pub mod preset;
pub mod render;
