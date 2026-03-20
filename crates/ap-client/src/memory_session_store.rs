use std::collections::HashMap;

use ap_noise::MultiDeviceTransport;
use ap_proxy_protocol::IdentityFingerprint;
use async_trait::async_trait;

use crate::error::ClientError;
use crate::traits::SessionStore;

struct SessionEntry {
    fingerprint: IdentityFingerprint,
    name: Option<String>,
    cached_at: u64,
    last_connected_at: u64,
    transport_state: Option<MultiDeviceTransport>,
}

/// In-memory session store that does not persist to disk.
///
/// Used for ephemeral connections where the session should not be saved.
pub struct MemorySessionStore {
    sessions: HashMap<IdentityFingerprint, SessionEntry>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.sessions.contains_key(fingerprint)
    }

    async fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), ClientError> {
        let now = crate::compat::now_seconds();
        self.sessions
            .entry(fingerprint)
            .and_modify(|e| e.cached_at = now)
            .or_insert(SessionEntry {
                fingerprint,
                name: None,
                cached_at: now,
                last_connected_at: now,
                transport_state: None,
            });
        Ok(())
    }

    async fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ClientError> {
        self.sessions.remove(fingerprint);
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), ClientError> {
        self.sessions.clear();
        Ok(())
    }

    async fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.sessions
            .values()
            .map(|s| {
                (
                    s.fingerprint,
                    s.name.clone(),
                    s.cached_at,
                    s.last_connected_at,
                )
            })
            .collect()
    }

    async fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), ClientError> {
        if let Some(session) = self.sessions.get_mut(fingerprint) {
            session.name = Some(name);
            Ok(())
        } else {
            Err(ClientError::SessionCache("Session not found".to_string()))
        }
    }

    async fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ClientError> {
        if let Some(session) = self.sessions.get_mut(fingerprint) {
            session.last_connected_at = crate::compat::now_seconds();
            Ok(())
        } else {
            Err(ClientError::SessionCache("Session not found".to_string()))
        }
    }

    async fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), ClientError> {
        if let Some(session) = self.sessions.get_mut(fingerprint) {
            session.transport_state = Some(transport_state);
            Ok(())
        } else {
            Err(ClientError::SessionCache("Session not found".to_string()))
        }
    }

    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, ClientError> {
        if let Some(session) = self.sessions.get(fingerprint) {
            match &session.transport_state {
                Some(state) => Ok(Some(state.clone())),
                None => Err(ClientError::SessionCache(
                    "No transport state stored for this session".to_string(),
                )),
            }
        } else {
            Err(ClientError::SessionCache("Session not found".to_string()))
        }
    }
}
