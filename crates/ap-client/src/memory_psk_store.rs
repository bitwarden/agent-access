use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::ClientError;
use crate::traits::{PskEntry, PskStore};
use crate::types::PskId;

/// In-memory PSK store that does not persist to disk.
///
/// Used for tests and examples where reusable PSKs should not be saved.
pub struct MemoryPskStore {
    entries: HashMap<PskId, PskEntry>,
}

impl MemoryPskStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl Default for MemoryPskStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PskStore for MemoryPskStore {
    async fn get(&self, psk_id: &PskId) -> Option<PskEntry> {
        self.entries.get(psk_id).cloned()
    }

    async fn save(&mut self, entry: PskEntry) -> Result<(), ClientError> {
        self.entries.insert(entry.psk_id.clone(), entry);
        Ok(())
    }

    async fn remove(&mut self, psk_id: &PskId) -> Result<(), ClientError> {
        self.entries.remove(psk_id);
        Ok(())
    }

    async fn list(&self) -> Vec<PskEntry> {
        self.entries.values().cloned().collect()
    }
}
