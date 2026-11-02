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
    /// Authentication Object ID of the session running the current command
    /// (all zeros = the default session). Set by the transport for each
    /// command; policies are evaluated for this owner. Not persisted.
    session_owner: [u8; 4],
}

/// RESERVED_ID_ECKEY_SESSION (kSE05x_AppletResID_KP_ECKEY_USER): the SE's
/// own NIST P-256 key pair used for ECKey session key agreement.
pub const RESERVED_ID_ECKEY_SESSION: [u8; 4] = [0x7F, 0xFF, 0x02, 0x01];

/// The SE's ECC attestation key pair (SSS_SE05X_RESID_ATTESTATION_KEY in Plug
/// & Trust): signs attested reads; hosts read its public key from the SE.
pub const RESERVED_ID_ATTESTATION_KEY: [u8; 4] = [0xF0, 0x00, 0x00, 0x12];

/// Applet-reserved objects the simulator manages itself. Hosts may read them
/// (public part, attributes, existence) but not create, replace, delete or
/// use them in generic crypto commands; only the applet's own flows use the
/// private keys.
pub const RESERVED_IDS: &[[u8; 4]] = &[RESERVED_ID_ECKEY_SESSION, RESERVED_ID_ATTESTATION_KEY];

pub fn is_reserved_id(id: &[u8]) -> bool {
    RESERVED_IDS.iter().any(|r| r[..] == *id)
}

fn default_curves() -> HashMap<u8, u8> {
    // P-192, P-224, P-256, P-384, P-521 fully parameterized.
    (0x01..=0x05).map(|id| (id, CURVE_PARAMS_COMPLETE)).collect()
}

/// Writes the persisted store without holding up the APDU being processed:
/// a background thread writes the latest snapshot of each store file. A
/// synchronous write in the command path took up to a second on a busy disk,
/// longer than hosts wait for an answer (NXP's T=1 stack then asks for a
/// retransmission).
///
/// - Snapshots are coalesced per destination path, so several stores in one
///   process never discard each other's updates.
/// - `flush_store` waits until a path has no queued or in-flight write; it runs
///   before a store file is loaded and when a persistent store is dropped, so
///   reopening a store never reads stale state.
/// - The file holds private keys and SCP03 keys: it is written to a temporary
///   file created with mode 0600 (or the existing file's mode), then renamed.
mod writer {
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::{Condvar, Mutex, OnceLock};

    #[derive(Default)]
    struct State {
        pending: HashMap<PathBuf, String>,
        in_flight: HashSet<PathBuf>,
    }

    struct Writer {
        state: Mutex<State>,
        cv: Condvar,
    }

    static WRITER: OnceLock<&'static Writer> = OnceLock::new();

    fn writer() -> &'static Writer {
        WRITER.get_or_init(|| {
            let w: &'static Writer = Box::leak(Box::new(Writer {
                state: Mutex::new(State::default()),
                cv: Condvar::new(),
            }));
            std::thread::spawn(move || run(w));
            w
        })
    }

    fn run(w: &'static Writer) {
        loop {
            let batch: Vec<(PathBuf, String)> = {
                let mut st = w.state.lock().unwrap_or_else(|e| e.into_inner());
                while st.pending.is_empty() {
                    st = w.cv.wait(st).unwrap_or_else(|e| e.into_inner());
                }
                let batch: Vec<_> = st.pending.drain().collect();
                for (p, _) in &batch {
                    st.in_flight.insert(p.clone());
                }
                batch
            };
            for (path, json) in &batch {
                write_file(path, json);
            }
            let mut st = w.state.lock().unwrap_or_else(|e| e.into_inner());
            for (p, _) in &batch {
                st.in_flight.remove(p);
            }
            w.cv.notify_all();
        }
    }

    fn write_file(path: &Path, json: &str) {
        use std::io::Write;
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        let _ = std::fs::remove_file(&tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let Ok(mut f) = opts.open(&tmp) else { return };
        // Keep the access restrictions of the file being replaced.
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = f.set_permissions(meta.permissions());
        }
        if f.write_all(json.as_bytes()).is_ok() && f.flush().is_ok() {
            drop(f);
            let _ = std::fs::rename(&tmp, path);
        } else {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
        }
    }

    pub fn write_store(path: &Path, json: String) {
        let w = writer();
        let mut st = w.state.lock().unwrap_or_else(|e| e.into_inner());
        st.pending.insert(path.to_path_buf(), json);
        w.cv.notify_all();
    }

    /// Blocks until `path` has no queued or in-flight write.
    pub fn flush_store(path: &Path) {
        let Some(w) = WRITER.get() else { return };
        let mut st = w.state.lock().unwrap_or_else(|e| e.into_inner());
        while st.pending.contains_key(path) || st.in_flight.contains(path) {
            st = w.cv.wait(st).unwrap_or_else(|e| e.into_inner());
        }
    }
}

use writer::{flush_store, write_store};

/// A persistent store finishes writing its file before it goes away, so a
/// store reopened on the same file (or an orderly shutdown) sees every update.
impl Drop for ObjectStore {
    fn drop(&mut self) {
        if let Some(path) = &self.persist_path {
            flush_store(path);
        }
    }
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
            session_owner: [0; 4],
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
            session_owner: [0; 4],
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
            .or_insert(ObjectMetadata { policy, origin, auth: None });
        self.persist();
    }

    /// Mark a freshly created object as an Authentication Object.
    pub fn set_auth_object(&mut self, id: [u8; 4], max_attempts: u16) {
        if let Some(m) = self.metadata.get_mut(&id) {
            let instance = rand::RngCore::next_u64(&mut rand::rngs::OsRng);
            m.auth = Some(crate::object_store::types::AuthState { max_attempts, attempts: 0, instance });
            self.persist();
        }
    }

    pub fn auth_state(&self, id: &[u8; 4]) -> Option<crate::object_store::types::AuthState> {
        self.metadata.get(id).and_then(|m| m.auth)
    }

    /// True when the Authentication Object has used up its attempts.
    pub fn auth_blocked(&self, id: &[u8; 4]) -> bool {
        matches!(self.auth_state(id), Some(a) if a.max_attempts != 0 && a.attempts >= a.max_attempts)
    }

    /// Count a failed authentication (only when a maximum is set).
    pub fn auth_failed(&mut self, id: &[u8; 4]) {
        if let Some(a) = self.metadata.get_mut(id).and_then(|m| m.auth.as_mut()) {
            if a.max_attempts != 0 && a.attempts < a.max_attempts {
                a.attempts += 1;
                self.persist();
            }
        }
    }

    /// A successful authentication resets the counter.
    pub fn auth_succeeded(&mut self, id: &[u8; 4]) {
        if let Some(a) = self.metadata.get_mut(id).and_then(|m| m.auth.as_mut()) {
            if a.attempts != 0 {
                a.attempts = 0;
                self.persist();
            }
        }
    }

    pub fn session_owner(&self) -> [u8; 4] {
        self.session_owner
    }

    pub fn set_session_owner(&mut self, owner: [u8; 4]) {
        self.session_owner = owner;
    }

    /// SE050_SIM_DEMO_AUTH=1: the demo Authentication Objects that NXP Plug &
    /// Trust's examples use (sss/ex/inc/ex_sss_auth.h, ex_sss_objid.h), so its
    /// UserID, AESKey and ECKey session modes can run against the simulator:
    /// 0x7DA00001 UserID C0 01 02 03 04, 0x7DA00002 AESKey 40..4F, 0x7DA00003
    /// ECKey with the public key of EX_SSS_AUTH_SE05X_KEY_HOST_ECDSA_KEY. No
    /// policy, unlimited attempts. Created once, like trust provisioning.
    pub fn ensure_demo_auth_objects(&mut self) {
        const USERID: [u8; 4] = [0x7D, 0xA0, 0x00, 0x01];
        const AESKEY: [u8; 4] = [0x7D, 0xA0, 0x00, 0x02];
        const ECKEY: [u8; 4] = [0x7D, 0xA0, 0x00, 0x03];
        const ECKEY_PUB: &str = "043c9e47edf051a3589f67302d22567c2e17229e8883338ec3b7d527f9ee71d0a81aae7fe21caa6677783aa88da6d6a8ad5ec53b10bc0b11094482f04d24b5bec4";
        if !self.objects.contains_key(&USERID) {
            self.objects.insert(USERID, SecureObject::UserID { value: vec![0xC0, 0x01, 0x02, 0x03, 0x04] });
            self.metadata.insert(USERID, ObjectMetadata { policy: None, origin: 0x03, auth: Some(Default::default()) });
        }
        if !self.objects.contains_key(&AESKEY) {
            self.objects.insert(AESKEY, SecureObject::AESKey { key: (0x40..=0x4F).collect() });
            self.metadata.insert(AESKEY, ObjectMetadata { policy: None, origin: 0x03, auth: Some(Default::default()) });
        }
        if !self.objects.contains_key(&ECKEY) {
            self.objects.insert(ECKEY, SecureObject::ECPublicKey {
                curve: crate::object_store::types::ECCurve::NistP256,
                public_key: hex::decode(ECKEY_PUB).unwrap_or_default(),
            });
            self.metadata.insert(ECKEY, ObjectMetadata { policy: None, origin: 0x03, auth: Some(Default::default()) });
        }
        self.persist();
    }

    /// The SE's own key pairs (ECKey session key agreement, attestation),
    /// created on first use and persisted.
    pub fn ensure_eckey_session_key(&mut self) {
        let mut changed = false;
        for id in [RESERVED_ID_ECKEY_SESSION, RESERVED_ID_ATTESTATION_KEY] {
            if self.objects.contains_key(&id) {
                continue;
            }
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let pk = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
            self.objects.insert(id, SecureObject::ECKeyPair {
                curve: crate::object_store::types::ECCurve::NistP256,
                private_key: sk.to_bytes().to_vec(),
                public_key: pk,
            });
            changed = true;
        }
        if changed {
            self.persist();
        }
    }

    pub fn metadata(&self, id: &[u8; 4]) -> Option<&ObjectMetadata> {
        self.metadata.get(id)
    }

    /// No attached policy means the applet default: everything for ordinary
    /// objects, read only for Authentication Objects (AN12543 table 17).
    /// Once a policy is attached, only the access rule of the current session
    /// owner applies (rules are not inherited across owners, AN12543 3.7.1.2);
    /// an owner without a rule, or an omitted permission, is a denial.
    pub fn policy_allows(&self, id: &[u8; 4], permission: u32) -> bool {
        let meta = self.metadata.get(id);
        match meta.and_then(|m| m.policy.as_deref()) {
            Some(raw) => crate::policy::ar_header_for(raw, &self.session_owner)
                .map(|header| header & permission != 0)
                .unwrap_or(false),
            None if meta.and_then(|m| m.auth).is_some() => permission == crate::policy::POLICY_OBJ_ALLOW_READ,
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
            write_store(path, json);
        }
    }

    fn load(&mut self) {
        let Some(path) = &self.persist_path else { return };
        flush_store(path);
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

    #[test]
    fn test_stores_on_different_paths_keep_their_latest_snapshot() {
        let a = unique_store_path("writer_path_a");
        let b = unique_store_path("writer_path_b");
        {
            let mut sa = ObjectStore::with_persistence(a.clone());
            let mut sb = ObjectStore::with_persistence(b.clone());
            for i in 0..50u8 {
                sa.insert([0, 0, 0xA0, i], SecureObject::Binary { data: vec![i] });
                sb.insert([0, 0, 0xB0, i], SecureObject::Binary { data: vec![i] });
            }
        }
        let sa = ObjectStore::with_persistence(a.clone());
        let sb = ObjectStore::with_persistence(b.clone());
        for i in 0..50u8 {
            assert!(sa.exists(&[0, 0, 0xA0, i]) && !sa.exists(&[0, 0, 0xB0, i]));
            assert!(sb.exists(&[0, 0, 0xB0, i]) && !sb.exists(&[0, 0, 0xA0, i]));
        }
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    #[test]
    fn test_reopen_sees_updates_of_a_store_still_open() {
        let path = unique_store_path("writer_reopen");
        let mut first = ObjectStore::with_persistence(path.clone());
        first.set_scp_required(true);
        let second = ObjectStore::with_persistence(path.clone());
        assert!(second.scp_required());
        drop(first);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn test_store_file_is_private_and_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let path = unique_store_path("writer_mode");
        let mode = |p: &PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        {
            let mut store = ObjectStore::with_persistence(path.clone());
            store.insert([0, 0, 0, 1], SecureObject::Binary { data: vec![1] });
        }
        assert_eq!(mode(&path), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        {
            let mut store = ObjectStore::with_persistence(path.clone());
            store.insert([0, 0, 0, 2], SecureObject::Binary { data: vec![2] });
        }
        assert_eq!(mode(&path), 0o640);
        assert!(ObjectStore::with_persistence(path.clone()).exists(&[0, 0, 0, 2]));
        let _ = std::fs::remove_file(&path);
    }
}
