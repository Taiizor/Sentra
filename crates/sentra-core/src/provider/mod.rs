//! Capability-scoped model provider abstraction and privacy-preserving gateway (REQ-F03, REQ-F08, REQ-F09, ADR-0005).

pub mod contract;
pub mod gateway;
pub mod local_endpoint;
pub mod mock;
pub mod redaction;

pub use contract::{
    Body, Capabilities, DataClass, Diagnostic, DiagnosticCode, ErrorKind, Failure, Feature, Format,
    Location, Model, Operation, Policy, Progress, Provider, Rates, Request, Response, Usage, Value,
};
pub use gateway::{Gateway, Ledger, LocalStatus, VirtualControl};
pub use local_endpoint::LocalInferenceEndpointProvider;
pub use mock::{
    MockFailure, Script, SharedTrace, SyntheticMockProvider, Terminal, Trace, full_model,
};
pub use redaction::RedactionFilter;
