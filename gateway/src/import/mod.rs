//! Pluggable API-description import. An [`Importer`] parses one IDL (OpenAPI, Smithy, …)
//! into hackamore's dialect-independent [`ApiModel`]. The importer is the *only* code that
//! knows an IDL's grammar; everything downstream (normalize, lint, the studio) sees only
//! the IR, so adding an IDL never touches the engine.

mod git;
pub use git::git_model;
mod openapi;
pub use openapi::OpenApiImporter;
mod smithy;
pub use smithy::SmithyImporter;

use hackamore_models::apimodel::ApiModel;

/// Which interface-description language an importer parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idl {
    OpenApi,
    Smithy,
}

/// Parse a raw API description into the IR. Implementations are **pure** — no I/O: fetching
/// the bytes (from a URL or file) is the caller's job, so importers stay trivially testable
/// and the registration path owns all the fail-closed network/filesystem handling.
pub trait Importer {
    /// Which IDL this importer parses.
    fn idl(&self) -> Idl;
    /// Turn a raw description into an [`ApiModel`], or explain why it can't.
    fn import(&self, raw: &[u8]) -> Result<ApiModel, ImportError>;
}

/// Why a description could not be turned into an [`ApiModel`].
#[derive(Debug)]
pub enum ImportError {
    /// The bytes were not the expected serialization (e.g. not JSON).
    Parse(String),
    /// The document parsed but declared no usable operations.
    Empty,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Parse(m) => write!(f, "could not parse description: {m}"),
            ImportError::Empty => write!(f, "description declared no operations"),
        }
    }
}

impl std::error::Error for ImportError {}
