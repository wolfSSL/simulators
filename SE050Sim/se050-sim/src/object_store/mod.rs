/* mod.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

pub mod types;

use std::collections::HashMap;
use std::path::PathBuf;
use types::SecureObject;

/// Hex-encoded 4-byte object ID used as JSON key.
type ObjectIdKey = String;

/// State for a transient crypto object (digest or cipher context).
#[derive(Debug, Clone)]
pub enum CryptoObjectState {
    Digest {
        algo: u8,
        data: Vec<u8>,
    },
    Cipher {
        encrypting: bool,
        key_id: [u8; 4],
        iv: Vec<u8>,
        accumulated: Vec<u8>,
    },
}

/// Object store backed by an in-memory HashMap with optional JSON file persistence.
pub struct ObjectStore {
    objects: HashMap<[u8; 4], SecureObject>,
    persist_path: Option<PathBuf>,
    /// Transient crypto objects (digest/cipher contexts), keyed by 2-byte crypto object ID.
    pub crypto_objects: HashMap<u16, CryptoObjectState>,
    /// Registry of created crypto object types (ID -> (context_type, subtype)).
    pub crypto_object_types: HashMap<u16, (u8, u8)>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            persist_path: None,
            crypto_objects: HashMap::new(),
            crypto_object_types: HashMap::new(),
        }
    }

    pub fn with_persistence(path: PathBuf) -> Self {
        let mut store = Self {
            objects: HashMap::new(),
            persist_path: Some(path.clone()),
            crypto_objects: HashMap::new(),
            crypto_object_types: HashMap::new(),
        };
        store.load();
        store
    }

    pub fn insert(&mut self, id: [u8; 4], obj: SecureObject) {
        self.objects.insert(id, obj);
        self.persist();
    }

    pub fn get(&self, id: &[u8; 4]) -> Option<&SecureObject> {
        self.objects.get(id)
    }

    pub fn get_mut(&mut self, id: &[u8; 4]) -> Option<&mut SecureObject> {
        self.objects.get_mut(id)
    }

    pub fn remove(&mut self, id: &[u8; 4]) -> Option<SecureObject> {
        let result = self.objects.remove(id);
        if result.is_some() {
            self.persist();
        }
        result
    }

    pub fn exists(&self, id: &[u8; 4]) -> bool {
        self.objects.contains_key(id)
    }

    pub fn list_ids(&self) -> Vec<[u8; 4]> {
        self.objects.keys().copied().collect()
    }

    pub fn clear(&mut self) {
        self.objects.clear();
        self.persist();
    }

    pub fn count(&self) -> usize {
        self.objects.len()
    }

    fn persist(&self) {
        let Some(path) = &self.persist_path else { return };
        let serializable: HashMap<ObjectIdKey, &SecureObject> = self
            .objects
            .iter()
            .map(|(k, v)| (hex::encode(k), v))
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&serializable) {
            let _ = std::fs::write(path, json);
        }
    }

    fn load(&mut self) {
        let Some(path) = &self.persist_path else { return };
        let Ok(json) = std::fs::read_to_string(path) else { return };
        let Ok(deserialized): Result<HashMap<ObjectIdKey, SecureObject>, _> =
            serde_json::from_str(&json)
        else {
            return;
        };
        for (hex_key, obj) in deserialized {
            if let Ok(bytes) = hex::decode(&hex_key) {
                if bytes.len() == 4 {
                    let mut id = [0u8; 4];
                    id.copy_from_slice(&bytes);
                    self.objects.insert(id, obj);
                }
            }
        }
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}
