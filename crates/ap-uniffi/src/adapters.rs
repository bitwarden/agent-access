//! Thin adapters that bridge FFI callback traits to `ap_client` trait interfaces.

use std::sync::Arc;

use ap_client::{ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate, IdentityProvider};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;

use crate::callbacks::{ConnectionStorage, FfiStoredConnection, IdentityStorage};

// ---------------------------------------------------------------------------
// IdentityStorage → IdentityProvider
// ---------------------------------------------------------------------------

pub struct CallbackIdentityProvider {
    keypair: IdentityKeyPair,
}

impl CallbackIdentityProvider {
    pub fn from_storage(storage: &dyn IdentityStorage) -> Result<Self, ClientError> {
        let keypair = if let Some(bytes) = storage.load_identity() {
            IdentityKeyPair::from_cose(&bytes).map_err(|_| {
                ClientError::IdentityStorageFailed(
                    "Failed to parse identity from stored bytes".to_string(),
                )
            })?
        } else {
            let keypair = IdentityKeyPair::generate();
            let cose_bytes = keypair.to_cose();
            storage.save_identity(cose_bytes).map_err(|e| {
                ClientError::IdentityStorageFailed(format!("Failed to save identity: {e}"))
            })?;
            keypair
        };

        Ok(Self { keypair })
    }
}

#[async_trait]
impl IdentityProvider for CallbackIdentityProvider {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

// ---------------------------------------------------------------------------
// ConnectionStorage → ConnectionStore
// ---------------------------------------------------------------------------

pub struct CallbackConnectionStore {
    storage: Arc<dyn ConnectionStorage>,
}

impl CallbackConnectionStore {
    pub fn new(storage: Arc<dyn ConnectionStorage>) -> Self {
        Self { storage }
    }
}

fn stored_to_info(stored: &FfiStoredConnection) -> Option<ConnectionInfo> {
    let fingerprint = IdentityFingerprint::from_hex(&stored.fingerprint).ok()?;
    let transport_state = stored.transport_state.as_ref().and_then(|bytes| {
        PersistentTransportState::from_bytes(bytes)
            .ok()
            .map(MultiDeviceTransport::from)
    });

    Some(ConnectionInfo {
        fingerprint,
        name: stored.name.clone(),
        cached_at: stored.cached_at,
        last_connected_at: stored.last_connected_at,
        transport_state,
    })
}

fn info_to_stored(info: &ConnectionInfo) -> FfiStoredConnection {
    let transport_state = info
        .transport_state
        .as_ref()
        .and_then(|t| PersistentTransportState::from(t).to_bytes().ok());

    FfiStoredConnection {
        fingerprint: info.fingerprint.to_hex(),
        name: info.name.clone(),
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state,
    }
}

#[async_trait]
impl ConnectionStore for CallbackConnectionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.storage
            .get(fingerprint.to_hex())
            .as_ref()
            .and_then(stored_to_info)
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let stored = info_to_stored(&connection);
        self.storage
            .save(stored)
            .map_err(|e| ClientError::ConnectionCache(e.to_string()))
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        self.storage
            .update(update.fingerprint.to_hex(), update.last_connected_at)
            .map_err(|e| ClientError::ConnectionCache(e.to_string()))
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.storage
            .list()
            .iter()
            .filter_map(stored_to_info)
            .collect()
    }
}
