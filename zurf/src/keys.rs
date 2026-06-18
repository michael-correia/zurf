// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::{
    mpdu::EncapsulationCommand,
    security::{
        Key,
        s2::{
            EncryptedEncapsulation, MpanState, NetworkKeyExpansion, NonceReport,
            PartialEntropyInput, SpanState,
        },
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
    keys: [Option<NetworkKeyExpansion>; 5],
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

pub trait KeyStore {
    fn cache_s2_nonce(&mut self, home: HomeId, source_node: NodeId, nonce: NonceReport);
    fn decrypt_s2(
        &mut self,
        is_lr: bool,
        home: HomeId,
        source_node: NodeId,
        mac_destination: &crate::types::Destination,
        encrypted_message: EncryptedEncapsulation,
        ciphertext: &[u8],
    ) -> EncapsulationCommand;

    fn insert_keyring(&mut self, home: HomeId, keyring: KeyRing);
}

pub struct LruKeyStore {
    keyrings: FixedKeyValueQueue<5, HomeId, KeyRing>,
    receivers_entropy: FixedKeyValueQueue<25, u64, (PartialEntropyInput, u8)>,
    spans: CLruCache<u64, SpanState>,
    mpans: CLruCache<u64, MpanState>,
}

impl std::default::Default for LruKeyStore {
    fn default() -> Self {
        Self {
            keyrings: FixedKeyValueQueue::default(),
            receivers_entropy: FixedKeyValueQueue::default(),
            spans: CLruCache::new(NonZeroUsize::new(64).unwrap()),
            mpans: CLruCache::new(NonZeroUsize::new(64).unwrap()),
        }
    }
}

fn insert_receiver_entropy(
    entropy_list: &mut FixedKeyValueQueue<25, u64, (PartialEntropyInput, u8)>,
    home: HomeId,
    node: NodeId,
    receiver_entropy: PartialEntropyInput,
    sequence_number: u8,
) {
    let key = (home.0 as u64) << 16 | (node.0 as u64);
    entropy_list.push(key, (receiver_entropy, sequence_number));
}

fn insert_span(
    spans: &mut CLruCache<u64, SpanState>,
    home: HomeId,
    sender_node: NodeId,
    receiver_node: NodeId,
    span_state: SpanState,
) {
    let bigger_node = sender_node.0.max(receiver_node.0);
    let smaller_node = sender_node.0.min(receiver_node.0);
    let key = (home.0 as u64) << 32 | (bigger_node as u64) << 16 | (smaller_node as u64);
    let _ = spans.put(key, span_state);
}

fn get_span(
    spans: &mut CLruCache<u64, SpanState>,
    home: HomeId,
    sender_node: NodeId,
    receiver_node: NodeId,
) -> Option<&mut SpanState> {
    let bigger_node = sender_node.0.max(receiver_node.0);
    let smaller_node = sender_node.0.min(receiver_node.0);
    let key = (home.0 as u64) << 32 | (bigger_node as u64) << 16 | (smaller_node as u64);
    spans.get_mut(&key)
}

fn insert_mpan(
    mpans: &mut CLruCache<u64, MpanState>,
    home: HomeId,
    sender_node: NodeId,
    group: u8,
    mpan_state: MpanState,
) {
    let key = (home.0 as u64) << 24 | (sender_node.0 as u64) << 8 | (group as u64);
    let _ = mpans.put(key, mpan_state);
}

fn get_mpan(
    mpans: &mut CLruCache<u64, MpanState>,
    home: HomeId,
    sender_node: NodeId,
    group: u8,
) -> Option<&mut MpanState> {
    let key = (home.0 as u64) << 24 | (sender_node.0 as u64) << 8 | (group as u64);
    mpans.get_mut(&key)
}

fn derive_span(
    is_lr: bool,
    receivers_entropy: PartialEntropyInput,
    receivers_sequence_number: u8,
    senders_entropy: &PartialEntropyInput,
    keyring: &KeyRing,
    encrypted_message: &EncryptedEncapsulation,
    ciphertext: &[u8],
) -> Option<(SpanState, Vec<u8>)> {
    let candidate_classes = if is_lr {
        &[
            crate::keys::SecurityClass::LrAuthenticated,
            crate::keys::SecurityClass::LrAccessControl,
        ][..]
    } else {
        &[
            crate::keys::SecurityClass::Unauthenticated,
            crate::keys::SecurityClass::MeshAuthenticated,
            crate::keys::SecurityClass::MeshAccessControl,
        ][..]
    };
    let mixed_entropy = receivers_entropy.with_senders_entropy(senders_entropy);
    candidate_classes
        .iter()
        .filter_map(|class| keyring[*class].as_ref().map(|expansion| (class, expansion)))
        .find_map(|(&class, key_expansion)| {
            SpanState::new(
                &mixed_entropy,
                key_expansion,
                class,
                encrypted_message.sequence_number,
                receivers_sequence_number,
                &encrypted_message.aad,
                ciphertext,
            )
        })
}

fn get_keyring(
    keyrings: &FixedKeyValueQueue<5, HomeId, KeyRing>,
    home: HomeId,
) -> Option<&KeyRing> {
    keyrings.get(&home)
}

fn get_receiver_entropy(
    receivers_entropy: &FixedKeyValueQueue<25, u64, (PartialEntropyInput, u8)>,
    home: HomeId,
    node: NodeId,
) -> Option<(PartialEntropyInput, u8)> {
    let key = (home.0 as u64) << 16 | (node.0 as u64);
    if let Some((entropy, sequence_number)) = receivers_entropy.get(&key) {
        Some((entropy.clone(), *sequence_number))
    } else {
        None
    }
}

fn insert_keyring(
    keyrings: &mut FixedKeyValueQueue<5, HomeId, KeyRing>,
    home: HomeId,
    keyring: KeyRing,
) {
    keyrings.push(home, keyring);
}

impl KeyStore for LruKeyStore {
    fn insert_keyring(&mut self, home: HomeId, keyring: KeyRing) {
        insert_keyring(&mut self.keyrings, home, keyring);
    }

    fn cache_s2_nonce(&mut self, home: HomeId, source_node: NodeId, nonce: NonceReport) {
        insert_receiver_entropy(
            &mut self.receivers_entropy,
            home,
            source_node,
            nonce.entropy,
            nonce.sequence_number,
        );
    }

    fn decrypt_s2(
        &mut self,
        is_lr: bool,
        home: HomeId,
        source_node: NodeId,
        mac_destination: &crate::types::Destination,
        mut encrypted_message: EncryptedEncapsulation,
        ciphertext: &[u8],
    ) -> EncapsulationCommand {
        // TODO store entropy and sequence numbers so SPAN state can be derived after receiving network keys via dbus
        let network_keys = get_keyring(&self.keyrings, home);
        if network_keys.is_none() {
            return EncapsulationCommand::Security2Encrypted(
                encrypted_message,
                ciphertext.to_vec(),
            );
        }

        let network_keys = &network_keys.unwrap();
        let group = &encrypted_message.get_multicast_group();
        match (group, &mac_destination) {
            (Some(group), _) => {
                if let Some(mpan) = get_mpan(&mut self.mpans, home, source_node, *group)
                    && let Some(key_expansion) = &network_keys[mpan.security_class]
                    && let Ok(plaintext) = mpan.decrypt_s2_frame(
                        key_expansion,
                        encrypted_message.aad.clone(),
                        ciphertext,
                    )
                {
                    // It is illegal to send MPAN state here, but we'll future-proof against unknown encrypted extensions
                    let plaintext = encrypted_message.extract_excrypted_extensions(&plaintext);
                    return EncapsulationCommand::Security2Decrypted(
                        encrypted_message,
                        Box::new(EncapsulationCommand::parse(
                            plaintext.to_vec(),
                            source_node,
                            mac_destination,
                            home,
                        )),
                    );
                }
            }
            (None, crate::types::Destination::Single(destination_node)) => {
                match encrypted_message.get_senders_entropy() {
                    Some(senders_entropy) => {
                        if let Some((receivers_entropy, receivers_sequence_number)) =
                            get_receiver_entropy(&self.receivers_entropy, home, *destination_node)
                            && let Some((span, plaintext)) = derive_span(
                                is_lr,
                                receivers_entropy,
                                receivers_sequence_number,
                                senders_entropy,
                                network_keys,
                                &encrypted_message,
                                ciphertext,
                            )
                        {
                            let security_class = span.security_class;
                            insert_span(
                                &mut self.spans,
                                home,
                                source_node,
                                *destination_node,
                                span,
                            );
                            let plaintext =
                                encrypted_message.extract_excrypted_extensions(&plaintext);
                            if let Some((group, mpan_state)) = encrypted_message.get_mpan_state() {
                                insert_mpan(
                                    &mut self.mpans,
                                    home,
                                    source_node,
                                    group,
                                    MpanState::new(*mpan_state, security_class),
                                );
                            }
                            return EncapsulationCommand::Security2Decrypted(
                                encrypted_message,
                                Box::new(EncapsulationCommand::parse(
                                    plaintext.to_vec(),
                                    source_node,
                                    mac_destination,
                                    home,
                                )),
                            );
                        }
                    }
                    None => {
                        if let Some(span) =
                            get_span(&mut self.spans, home, source_node, *destination_node)
                            && let Some(nk_expansion) = network_keys[span.security_class]
                            && let Ok(plaintext) = span.decrypt_s2_frame(
                                &nk_expansion,
                                encrypted_message.sequence_number,
                                &encrypted_message.aad,
                                ciphertext,
                            )
                        {
                            let security_class = span.security_class;
                            let plaintext =
                                encrypted_message.extract_excrypted_extensions(&plaintext);
                            if let Some((group, mpan_state)) = encrypted_message.get_mpan_state() {
                                insert_mpan(
                                    &mut self.mpans,
                                    home,
                                    source_node,
                                    group,
                                    MpanState::new(*mpan_state, security_class),
                                );
                            }
                            return EncapsulationCommand::Security2Decrypted(
                                encrypted_message,
                                Box::new(EncapsulationCommand::parse(
                                    plaintext.to_vec(),
                                    source_node,
                                    mac_destination,
                                    home,
                                )),
                            );
                        }
                    }
                };
            }
            _ => {}
        }
        EncapsulationCommand::Security2Encrypted(encrypted_message, ciphertext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Key, s2::PartialEntropyInput};

    #[test]
    fn test_keystore_s2_decryption() {
        let permanent_network_key = Key::new(hex_literal::hex!("e0ff431eb430fa03c85f519adc3aa518"));
        let public_entropy =
            PartialEntropyInput::new(hex_literal::hex!("2fb9b45a6d0a12b789cbc1ce4f2e0b51"));

        let mut keystore = LruKeyStore::default();
        insert_receiver_entropy(
            &mut keystore.receivers_entropy,
            HomeId(0xfdd09bc7),
            NodeId(1),
            public_entropy,
            0,
        );

        let keyring = KeyRing::new(Some(permanent_network_key), None, None, None, None);
        insert_keyring(&mut keystore.keyrings, HomeId(0xfdd09bc7), keyring);

        // Frame 1 S2 Payload (43 bytes): 0x9F, 0x03, S2 Header (20 bytes), Ciphertext (21 bytes)
        let raw_s2_payload = hex_literal::hex!(
            "9f 03 7d 01 12 41 63 4f 03 d2 40 7d f9 d6 b2 11 95 ce 68 87 eb 71 \
             93 16 48 dc 81 41 11 d4 c4 dc be 47 a9 42 db ac 58 6a 35 e0 2a"
        );

        // Deserialize the S2 command payload
        let (encrypted_message, ciphertext) = EncryptedEncapsulation::deserialize(
            &raw_s2_payload,
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            HomeId(0xfdd09bc7),
        )
        .unwrap();

        let dec_cmd = keystore.decrypt_s2(
            false, // is_lr
            HomeId(0xfdd09bc7),
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            encrypted_message,
            ciphertext,
        );

        // Verify decryption succeeded and returned a Decrypted payload
        let _decrypted_message = match dec_cmd {
            EncapsulationCommand::Security2Decrypted(msg, _) => msg,
            _ => panic!("Expected Security2Decrypted"),
        };

        // Verify the SpanState was successfully saved in the keystore
        let span = get_span(
            &mut keystore.spans,
            HomeId(0xfdd09bc7),
            NodeId(2),
            NodeId(1),
        )
        .unwrap()
        .clone();
        assert_eq!(span.get_original_sender_sequence_number(), 0x7D);
        assert_eq!(
            span.security_class,
            crate::keys::SecurityClass::Unauthenticated
        );

        // Now test second frame decryption
        let keyring = get_keyring(&keystore.keyrings, HomeId(0xfdd09bc7)).unwrap();
        let key_expansion = keyring[span.security_class].as_ref().unwrap();

        let mut second_drbg = span.get_drbg().clone();
        let second_nonce: [u8; 13] = second_drbg.generate();

        let plaintext_2 = [0x01, 0x02, 0x03];
        let s2_header_2 = [0x7E, 0x00];

        let mut aad_2 = Vec::new();
        aad_2.push(2u8); // Sender Node ID
        aad_2.push(1u8); // Receiver Node ID
        aad_2.extend_from_slice(&0xfdd09bc7u32.to_be_bytes()); // Home ID
        let total_s2_len_2 = 2 + 2 + plaintext_2.len() + 8;
        aad_2.extend_from_slice(&(total_s2_len_2 as u16).to_be_bytes());
        aad_2.extend_from_slice(&s2_header_2);

        use aes::cipher::KeyInit;
        use ccm::aead::Aead;
        let cipher_ccm = crate::security::s2::Aes128Ccm::new(&key_expansion.ccm_key.0.into());
        let payload_ccm = ccm::aead::Payload {
            msg: &plaintext_2,
            aad: &aad_2,
        };
        let ciphertext_2 = cipher_ccm
            .encrypt(&second_nonce.into(), payload_ccm)
            .unwrap();

        // Reconstruct S2 Payload 2
        let mut raw_s2_payload_2 = vec![0x9F, 0x03];
        raw_s2_payload_2.extend_from_slice(&s2_header_2);
        raw_s2_payload_2.extend_from_slice(&ciphertext_2);

        let (encrypted_message_2, ciphertext_2) = EncryptedEncapsulation::deserialize(
            &raw_s2_payload_2,
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            HomeId(0xfdd09bc7),
        )
        .unwrap();

        let dec_cmd_2 = keystore.decrypt_s2(
            false,
            HomeId(0xfdd09bc7),
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            encrypted_message_2,
            ciphertext_2,
        );

        assert!(matches!(
            dec_cmd_2,
            EncapsulationCommand::Security2Decrypted(..)
        ));

        let span_after = get_span(
            &mut keystore.spans,
            HomeId(0xfdd09bc7),
            NodeId(2),
            NodeId(1),
        )
        .unwrap();
        assert_eq!(span_after.get_original_sender_sequence_number(), 0x7E);
    }

    #[test]
    fn test_keystore_s2_routed_decryption() {
        let permanent_network_key = Key::new(hex_literal::hex!("e0ff431eb430fa03c85f519adc3aa518"));
        let public_entropy =
            PartialEntropyInput::new(hex_literal::hex!("2fb9b45a6d0a12b789cbc1ce4f2e0b51"));

        let mut keystore = LruKeyStore::default();
        insert_receiver_entropy(
            &mut keystore.receivers_entropy,
            HomeId(0xfdd09bc7),
            NodeId(1),
            public_entropy,
            0,
        );

        let keyring = KeyRing::new(Some(permanent_network_key), None, None, None, None);
        insert_keyring(&mut keystore.keyrings, HomeId(0xfdd09bc7), keyring);

        // Frame 1: Establish SPAN via singlecast handshake
        let raw_s2_payload = hex_literal::hex!(
            "9f 03 7d 01 12 41 63 4f 03 d2 40 7d f9 d6 b2 11 95 ce 68 87 eb 71 \
             93 16 48 dc 81 41 11 d4 c4 dc be 47 a9 42 db ac 58 6a 35 e0 2a"
        );

        let (encrypted_message, ciphertext) = EncryptedEncapsulation::deserialize(
            &raw_s2_payload,
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            HomeId(0xfdd09bc7),
        )
        .unwrap();

        let dec_cmd = keystore.decrypt_s2(
            false,
            HomeId(0xfdd09bc7),
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            encrypted_message,
            ciphertext,
        );

        assert!(matches!(
            dec_cmd,
            EncapsulationCommand::Security2Decrypted(..)
        ));

        // Get SPAN to encrypt Frame 2 (Routed)
        let span = get_span(
            &mut keystore.spans,
            HomeId(0xfdd09bc7),
            NodeId(2),
            NodeId(1),
        )
        .unwrap()
        .clone();

        let keyring = get_keyring(&keystore.keyrings, HomeId(0xfdd09bc7)).unwrap();
        let key_expansion = keyring[span.security_class].as_ref().unwrap();

        let mut second_drbg = span.get_drbg().clone();
        let second_nonce: [u8; 13] = second_drbg.generate();

        let plaintext_2 = [0x01, 0x02, 0x03];
        let s2_header_2 = [0x7E, 0x00];

        let mut aad_2 = Vec::new();
        aad_2.push(2u8); // Sender Node ID
        aad_2.push(1u8); // Receiver Node ID
        aad_2.extend_from_slice(&0xfdd09bc7u32.to_be_bytes()); // Home ID
        let total_s2_len_2 = 2 + 2 + plaintext_2.len() + 8;
        aad_2.extend_from_slice(&(total_s2_len_2 as u16).to_be_bytes());
        aad_2.extend_from_slice(&s2_header_2);

        use aes::cipher::KeyInit;
        use ccm::aead::Aead;
        let cipher_ccm = crate::security::s2::Aes128Ccm::new(&key_expansion.ccm_key.0.into());
        let payload_ccm = ccm::aead::Payload {
            msg: &plaintext_2,
            aad: &aad_2,
        };
        let ciphertext_2 = cipher_ccm
            .encrypt(&second_nonce.into(), payload_ccm)
            .unwrap();

        // Reconstruct S2 Payload 2
        let mut raw_s2_payload_2 = vec![0x9F, 0x03];
        raw_s2_payload_2.extend_from_slice(&s2_header_2);
        raw_s2_payload_2.extend_from_slice(&ciphertext_2);

        let (encrypted_message_2, ciphertext_2) = EncryptedEncapsulation::deserialize(
            &raw_s2_payload_2,
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            HomeId(0xfdd09bc7),
        )
        .unwrap();

        let dec_cmd_2 = keystore.decrypt_s2(
            false,
            HomeId(0xfdd09bc7),
            NodeId(2),
            &crate::types::Destination::Single(NodeId(1)),
            encrypted_message_2,
            ciphertext_2,
        );

        assert!(matches!(
            dec_cmd_2,
            EncapsulationCommand::Security2Decrypted(..)
        ));

        let span_after = get_span(
            &mut keystore.spans,
            HomeId(0xfdd09bc7),
            NodeId(2),
            NodeId(1),
        )
        .unwrap();
        assert_eq!(span_after.get_original_sender_sequence_number(), 0x7E);
    }
}
