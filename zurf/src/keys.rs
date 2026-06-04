// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::{
    security::{
        Key, s2::MpanState, s2::NetworkKeyExpansion, s2::PartialEntropyInput, s2::SpanState,
    },
    types::{FixedKeyValueQueue, HomeId, NodeId},
};
use zurf_enum_derive::TryFromU8;

// will use to store SPANs and MPANs
use clru::CLruCache;
use std::num::NonZeroUsize;

#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityClass {
    Unauthenticated = 0,
    MeshAuthenticated = 1,
    MeshAccessControl = 2,
    LrAuthenticated = 3,
    LrAccessControl = 4,
}

#[derive(Default, Clone)]
pub struct KeyRing {
    pub keys: [Option<NetworkKeyExpansion>; 5],
}

impl KeyRing {
    pub fn new(
        unauthenticated_key: Option<Key>,
        mesh_authenticated_key: Option<Key>,
        mesh_access_control_key: Option<Key>,
        lr_authenticated_key: Option<Key>,
        lr_access_control_key: Option<Key>,
    ) -> Self {
        Self {
            keys: [
                unauthenticated_key.map(|key| NetworkKeyExpansion::new(&key)),
                mesh_authenticated_key.map(|key| NetworkKeyExpansion::new(&key)),
                mesh_access_control_key.map(|key| NetworkKeyExpansion::new(&key)),
                lr_authenticated_key.map(|key| NetworkKeyExpansion::new(&key)),
                lr_access_control_key.map(|key| NetworkKeyExpansion::new(&key)),
            ],
        }
    }
}

impl std::ops::Index<SecurityClass> for KeyRing {
    type Output = Option<NetworkKeyExpansion>;

    fn index(&self, index: SecurityClass) -> &Self::Output {
        &self.keys[index as usize]
    }
}

impl std::ops::IndexMut<SecurityClass> for KeyRing {
    fn index_mut(&mut self, index: SecurityClass) -> &mut Self::Output {
        &mut self.keys[index as usize]
    }
}

pub struct KeyStore {
    keyrings: FixedKeyValueQueue<5, HomeId, KeyRing>,
    receivers_entropy: FixedKeyValueQueue<25, u64, (PartialEntropyInput, u8)>,
    spans: CLruCache<u64, SpanState>,
    mpans: CLruCache<u64, MpanState>,
}

impl std::default::Default for KeyStore {
    fn default() -> Self {
        Self {
            keyrings: FixedKeyValueQueue::default(),
            receivers_entropy: FixedKeyValueQueue::default(),
            spans: CLruCache::new(NonZeroUsize::new(64).unwrap()),
            mpans: CLruCache::new(NonZeroUsize::new(64).unwrap()),
        }
    }
}

impl KeyStore {
    pub fn insert_keyring(&mut self, home_id: HomeId, keyring: KeyRing) {
        self.keyrings.push(home_id, keyring);
    }
    pub fn get_keyring(&self, home_id: &HomeId) -> Option<KeyRing> {
        self.keyrings.get(home_id).cloned()
    }

    pub fn insert_receiver_entropy(
        &mut self,
        home_id: &HomeId,
        node_id: &NodeId,
        receiver_entropy: PartialEntropyInput,
        sequence_number: u8,
    ) {
        let key = (home_id.0 as u64) << 16 | (node_id.0 as u64);
        self.receivers_entropy
            .push(key, (receiver_entropy, sequence_number));
    }

    pub fn get_receiver_entropy(
        &self,
        home_id: &HomeId,
        node_id: &NodeId,
    ) -> Option<(PartialEntropyInput, u8)> {
        let key = (home_id.0 as u64) << 16 | (node_id.0 as u64);
        if let Some((entropy, sequence_number)) = self.receivers_entropy.get(&key) {
            Some((entropy.clone(), *sequence_number))
        } else {
            None
        }
    }

    pub fn insert_span(
        &mut self,
        home_id: &HomeId,
        sender_node_id: &NodeId,
        receiver_node_id: &NodeId,
        span_state: SpanState,
    ) {
        let bigger_node = sender_node_id.0.max(receiver_node_id.0);
        let smaller_node = sender_node_id.0.min(receiver_node_id.0);
        let key = (home_id.0 as u64) << 32 | (bigger_node as u64) << 16 | (smaller_node as u64);
        let _ = self.spans.put(key, span_state);
    }

    pub fn get_span(
        &mut self,
        home_id: &HomeId,
        sender_node_id: &NodeId,
        receiver_node_id: &NodeId,
    ) -> Option<&mut SpanState> {
        let bigger_node = sender_node_id.0.max(receiver_node_id.0);
        let smaller_node = sender_node_id.0.min(receiver_node_id.0);
        let key = (home_id.0 as u64) << 32 | (bigger_node as u64) << 16 | (smaller_node as u64);
        self.spans.get_mut(&key)
    }
}
