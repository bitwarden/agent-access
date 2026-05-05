//! Shared wire protocol types for the ap-relay WebSocket server.
//!
//! This crate contains the protocol types used by both the relay server
//! and relay client, with zero TLS dependencies.

pub mod auth;
pub mod error;
pub mod messages;
pub mod rendezvous;

pub use auth::{
    Challenge, ChallengeResponse, Identity, IdentityFingerprint, IdentityKeyPair,
    SignatureAlgorithm,
};
pub use error::RelayError;
pub use messages::Messages;
pub use rendezvous::RendezvousCode;
