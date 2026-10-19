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
use crate::applet::AppletVersion;
use crate::scp03::keys::Scp03Config;
use types::{ObjectMetadata, SecureObject};

/// Hex-encoded 4-byte object ID used as JSON key.
type ObjectIdKey = String;

/// All five EC curve parameters (A, B, G, N, PRIME) present, matching
/// the kSE05x_ECCurveParam bit assignments.
pub const CURVE_PARAMS_COMPLETE: u8 = 0x1F;

/// State for a transient crypto object (digest, cipher, or MAC context).
#[derive(Debug, Clone)]
pub enum CryptoObjectState {
    Digest {
        algo: u8,
        data: Vec<u8>,
    },
    Cipher {
        encrypting: bool,
        mode: u8,
        key_id: [u8; 4],
        /// CBC chaining vector / CTR counter, advanced as blocks are
        /// processed across CipherUpdate calls.
        chain: Vec<u8>,
        /// Input bytes not yet processed (less than one block).
        pending: Vec<u8>,
    },
    Mac {
        algo: u8,
        validate: bool,
        key_id: [u8; 4],
        data: Vec<u8>,
    },
}

/// Object store backed by an in-memory HashMap with optional JSON file persistence.
pub struct ObjectStore {
    objects: HashMap<[u8; 4], SecureObject>,
    /// Creation-time policy and origin. Kept separate from SecureObject so
    /// policy behavior is uniform across every object type and persistence
    /// remains backward-compatible with old enum payloads.
    metadata: HashMap<[u8; 4], ObjectMetadata>,
    persist_path: Option<PathBuf>,
    /// EC curve objects: curve ID -> bitmask of uploaded parameters
    /// (kSE05x_ECCurveParam bits; CURVE_PARAMS_COMPLETE = usable).
    /// Real applets ship with no curves created; the simulator
    /// pre-provisions its supported NIST curves so hosts that predate
    /// curve management keep working out of the box.
    ec_curves: HashMap<u8, u8>,
    /// Transient crypto objects (digest/cipher/MAC contexts), keyed by 2-byte crypto object ID.
    pub crypto_objects: HashMap<u16, CryptoObjectState>,
    /// Registry of created crypto object types (ID -> (context_type, subtype)).
    pub crypto_object_types: HashMap<u16, (u8, u8)>,
    /// SetPlatformSCPRequest state: when true, plain (non-SCP03) commands are
    /// refused. Persisted, matching the boot-persistent flag on real silicon.
    scp_required: bool,
    /// Rotated Platform SCP03 keys. None selects the applet-personality
    /// defaults (or environment overrides). Factory reset deliberately does
    /// not restore these keys, matching the irrecoverable real-card behavior.
    platform_scp: Option<Scp03Config>,
}

fn default_curves() -> HashMap<u8, u8> {
    // P-192, P-224, P-256, P-384, P-521 fully parameterized.
    (0x01..=0x05).map(|id| (id, CURVE_PARAMS_COMPLETE)).collect()
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            metadata: HashMap::new(),
            persist_path: None,
            ec_curves: default_curves(),
            crypto_objects: HashMap::new(),
            crypto_object_types: HashMap::new(),
            scp_required: false,
            platform_scp: None,
        }
    }

    pub fn with_persistence(path: PathBuf) -> Self {
        let mut store = Self {
            objects: HashMap::new(),
            metadata: HashMap::new(),
            persist_path: Some(path.clone()),
            ec_curves: default_curves(),
            crypto_objects: HashMap::new(),
            crypto_object_types: HashMap::new(),
            scp_required: false,
            platform_scp: None,
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

    /// Record immutable object metadata on first creation. Repeated RSA
    /// component writes and ordinary overwrites cannot replace the policy.
    pub fn set_creation_metadata(
        &mut self,
        id: [u8; 4],
        policy: Option<Vec<u8>>,
        origin: u8,
    ) {
        self.metadata
            .entry(id)
            .or_insert(ObjectMetadata { policy, origin });
        self.persist();
    }

    pub fn metadata(&self, id: &[u8; 4]) -> Option<&ObjectMetadata> {
        self.metadata.get(id)
    }

    /// No attached policy means the applet default allows the operation.
    /// Once a policy is attached, an omitted permission is a denial.
    pub fn policy_allows(&self, id: &[u8; 4], permission: u32) -> bool {
        match self.metadata.get(id).and_then(|m| m.policy.as_deref()) {
            Some(raw) => crate::policy::ar_header_union(raw)
                .map(|header| header & permission != 0)
                .unwrap_or(false),
            None => true,
        }
    }

    pub fn remove(&mut self, id: &[u8; 4]) -> Option<SecureObject> {
        let result = self.objects.remove(id);
        if result.is_some() {
            self.metadata.remove(id);
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
        // DeleteAll on a real applet also deletes created curves and
        // crypto objects. The simulator re-provisions its default
        // curve set afterwards (see ec_curves) so key generation keeps
        // working for hosts that never create curves themselves.
        self.objects.clear();
        self.metadata.clear();
        self.ec_curves = default_curves();
        self.crypto_objects.clear();
        self.crypto_object_types.clear();
        self.persist();
    }

    pub fn count(&self) -> usize {
        self.objects.len()
    }

    // ---- EC curve object state ----

    /// Curve exists (parameterized or not). A created but param-less
    /// curve still shows as SET in ReadECCurveList on real applets.
    pub fn curve_exists(&self, curve_id: u8) -> bool {
        self.ec_curves.contains_key(&curve_id)
    }

    /// Curve exists and all five parameters have been uploaded; only
    /// then do key operations on it succeed (bench-verified: keygen on
    /// a param-less curve fails 0x6985 on applet 3.1.1 and 7.2.0).
    pub fn curve_ready(&self, curve_id: u8) -> bool {
        self.ec_curves.get(&curve_id) == Some(&CURVE_PARAMS_COMPLETE)
    }

    /// Create a curve object with no parameters uploaded yet.
    pub fn curve_create(&mut self, curve_id: u8) {
        self.ec_curves.insert(curve_id, 0);
        self.persist();
    }

    /// Reset an existing curve to the parameter-less state (applet
    /// 3.1.1 duplicate-CreateECCurve behavior).
    pub fn curve_reset(&mut self, curve_id: u8) {
        self.ec_curves.insert(curve_id, 0);
        self.persist();
    }

    /// Record an uploaded curve parameter (kSE05x_ECCurveParam bit).
    pub fn curve_add_param(&mut self, curve_id: u8, param: u8) {
        if let Some(mask) = self.ec_curves.get_mut(&curve_id) {
            *mask |= param & CURVE_PARAMS_COMPLETE;
            self.persist();
        }
    }

    pub fn curve_delete(&mut self, curve_id: u8) -> bool {
        let removed = self.ec_curves.remove(&curve_id).is_some();
        if removed {
            self.persist();
        }
        removed
    }

    // ---- Platform SCP03 required flag ----

    pub fn scp_required(&self) -> bool {
        self.scp_required
    }

    pub fn set_scp_required(&mut self, required: bool) {
        self.scp_required = required;
        self.persist();
    }

    pub fn platform_scp_config(&self, version: AppletVersion) -> Scp03Config {
        self.platform_scp
            .clone()
            .unwrap_or_else(|| Scp03Config::from_env(version))
    }

    pub fn set_platform_scp_config(&mut self, config: Scp03Config) {
        self.platform_scp = Some(config);
        self.persist();
    }

    fn persist(&self) {
        let Some(path) = &self.persist_path else { return };
        let objects: HashMap<ObjectIdKey, &SecureObject> = self
            .objects
            .iter()
            .map(|(k, v)| (hex::encode(k), v))
            .collect();
        let curves: HashMap<String, u8> = self
            .ec_curves
            .iter()
            .map(|(k, v)| (format!("{:02x}", k), *v))
            .collect();
        let metadata: HashMap<ObjectIdKey, &ObjectMetadata> = self
            .metadata
            .iter()
            .map(|(k, v)| (hex::encode(k), v))
            .collect();
        let doc = serde_json::json!({
            "objects": objects,
            "metadata": metadata,
            "ec_curves": curves,
            "scp_required": self.scp_required,
            "platform_scp": self.platform_scp,
        });
        if let Ok(json) = serde_json::to_string_pretty(&doc) {
            let _ = std::fs::write(path, json);
        }
    }

    fn load(&mut self) {
        let Some(path) = &self.persist_path else { return };
        let Ok(json) = std::fs::read_to_string(path) else { return };
        let Ok(value): Result<serde_json::Value, _> = serde_json::from_str(&json) else {
            return;
        };

        // Current schema: {"objects": {...}, "ec_curves": {...}}.
        // Legacy schema (pre curve-state): a flat hex-id -> object map.
        let objects_value = if value.get("objects").is_some() {
            // Additive since a later schema version; absent in older files.
            self.scp_required = value
                .get("scp_required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            self.platform_scp = value
                .get("platform_scp")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            if let Some(curves) = value.get("ec_curves").and_then(|v| v.as_object()) {
                self.ec_curves = curves
                    .iter()
                    .filter_map(|(k, v)| {
                        let id = u8::from_str_radix(k, 16).ok()?;
                        let mask = v.as_u64()? as u8;
                        Some((id, mask))
                    })
                    .collect();
            }
            if let Some(metadata) = value.get("metadata").and_then(|v| v.as_object()) {
                for (hex_key, metadata_value) in metadata {
                    let Ok(bytes) = hex::decode(hex_key) else { continue };
                    if bytes.len() != 4 {
                        continue;
                    }
                    let Ok(metadata) = serde_json::from_value::<ObjectMetadata>(
                        metadata_value.clone(),
                    ) else {
                        continue;
                    };
                    let mut id = [0u8; 4];
                    id.copy_from_slice(&bytes);
                    self.metadata.insert(id, metadata);
                }
            }
            value.get("objects").cloned().unwrap_or_default()
        } else {
            value
        };

        let Ok(deserialized): Result<HashMap<ObjectIdKey, SecureObject>, _> =
            serde_json::from_value(objects_value)
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

#[cfg(test)]
mod persistence_tests {
    use super::*;

    /// Unique per-invocation store path so concurrent `cargo test`
    /// processes cannot interfere through a shared temp file.
    fn unique_store_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!(
            "se050_sim_{}_{}_{}.json",
            tag,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn test_legacy_flat_store_file_still_loads() {
        // Pre-curve-state store files are a flat hex-id -> object map;
        // they must keep loading (with the default curve set) so
        // existing on-disk stores survive the schema change.
        let path = unique_store_path("legacy_store_test");
        let legacy = r#"{
            "00000042": { "Binary": { "data": [1, 2, 3] } }
        }"#;
        std::fs::write(&path, legacy).unwrap();

        let store = ObjectStore::with_persistence(path.clone());
        match store.get(&[0, 0, 0, 0x42]) {
            Some(SecureObject::Binary { data }) => assert_eq!(data, &vec![1, 2, 3]),
            other => panic!("legacy object missing: {:?}", other.is_some()),
        }
        assert!(store.curve_ready(0x03), "default curves provisioned");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_curve_state_round_trips_through_persistence() {
        let path = unique_store_path("curve_store_test");
        {
            let mut store = ObjectStore::with_persistence(path.clone());
            store.curve_delete(0x01);
            store.curve_create(0x06); // brainpool160r1, param-less
        }
        let store = ObjectStore::with_persistence(path.clone());
        assert!(!store.curve_exists(0x01));
        assert!(store.curve_exists(0x06));
        assert!(!store.curve_ready(0x06));
        assert!(store.curve_ready(0x03));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_policy_metadata_round_trips_and_is_removed_with_object() {
        let path = unique_store_path("metadata_store_test");
        let id = [0, 0, 0, 0x43];
        let policy = vec![
            0x08, 0, 0, 0, 0, 0x00, 0x20, 0x00, 0x00,
        ];
        {
            let mut store = ObjectStore::with_persistence(path.clone());
            store.insert(id, SecureObject::Binary { data: vec![1, 2, 3] });
            store.set_creation_metadata(id, Some(policy.clone()), 0x02);
        }
        {
            let mut store = ObjectStore::with_persistence(path.clone());
            let metadata = store.metadata(&id).expect("metadata missing");
            assert_eq!(metadata.policy.as_deref(), Some(policy.as_slice()));
            assert_eq!(metadata.origin, 0x02);
            assert!(store.policy_allows(&id, crate::policy::POLICY_OBJ_ALLOW_READ));
            assert!(!store.policy_allows(&id, crate::policy::POLICY_OBJ_ALLOW_DELETE));
            assert!(store.remove(&id).is_some());
        }
        let store = ObjectStore::with_persistence(path.clone());
        assert!(store.metadata(&id).is_none());
        let _ = std::fs::remove_file(&path);
    }


    #[test]
    fn test_platform_scp_keys_round_trip_and_survive_clear() {
        let path = unique_store_path("scp_keys_store_test");
        let config = Scp03Config {
            kvn: 0x0c,
            enc: vec![0x11; 16],
            mac: vec![0x22; 16],
            dek: vec![0x33; 16],
        };
        {
            let mut store = ObjectStore::with_persistence(path.clone());
            store.set_platform_scp_config(config.clone());
            store.clear();
        }
        let store = ObjectStore::with_persistence(path.clone());
        let loaded = store.platform_scp_config(AppletVersion::V7_2_22F);
        assert_eq!(loaded.kvn, config.kvn);
        assert_eq!(loaded.enc, config.enc);
        assert_eq!(loaded.mac, config.mac);
        assert_eq!(loaded.dek, config.dek);
        let _ = std::fs::remove_file(&path);
    }
}
