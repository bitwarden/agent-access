//! Relay client trait and default implementation
//!
//! This module provides the `RelayClient` trait for abstracting relay communication,
//! enabling dependency injection and easier testing.

use ap_relay_client::IncomingMessage;
#[cfg(feature = "native-websocket")]
use ap_relay_client::RelayProtocolClient;
use ap_relay_protocol::{IdentityFingerprint, IdentityKeyPair, RendezvousCode};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::ClientError;

/// Trait abstracting the relay client for communication between devices
#[async_trait]
pub trait RelayClient: Send + Sync {
    /// Connect to the relay server, returning a receiver for incoming messages
    async fn connect(
        &mut self,
        identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError>;

    /// Request a rendezvous code from the relay server
    async fn request_rendezvous(&self) -> Result<(), ClientError>;

    /// Request the identity associated with a rendezvous code
    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError>;

    /// Send a message to a peer by their fingerprint
    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError>;

    /// Disconnect from the relay server
    async fn disconnect(&mut self) -> Result<(), ClientError>;
}

/// Default implementation using RelayProtocolClient from ap-relay
#[cfg(feature = "native-websocket")]
pub struct DefaultRelayClient {
    inner: RelayProtocolClient,
}

#[cfg(feature = "native-websocket")]
impl DefaultRelayClient {
    pub fn from_url(relay_url: String) -> Self {
        Self {
            inner: RelayProtocolClient::from_url(relay_url),
        }
    }
}

#[cfg(feature = "native-websocket")]
#[async_trait]
impl RelayClient for DefaultRelayClient {
    async fn connect(
        &mut self,
        identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
        self.inner
            .connect(identity)
            .await
            .map_err(ClientError::from)
    }

    async fn request_rendezvous(&self) -> Result<(), ClientError> {
        self.inner
            .request_rendezvous()
            .await
            .map_err(ClientError::from)
    }

    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError> {
        self.inner
            .request_identity(code)
            .await
            .map_err(ClientError::from)
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.inner
            .send_to(fingerprint, data)
            .await
            .map_err(ClientError::from)
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.inner.disconnect().await.map_err(ClientError::from)
    }
}
