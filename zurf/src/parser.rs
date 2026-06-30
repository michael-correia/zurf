// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::frame::{Frame, FrameType};
use crate::keys::{KeyStore, LruKeyStore};
use crate::mpdu::{EncapsulationCommand, TransportServiceEncapsulation};
use crate::types::{Destination, FixedKeyValueQueue, HomeId, NodeId, ParseError, ParseResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportServiceCache {
    pub sender: NodeId,
    pub destination: Destination,
    pub home: HomeId,
    pub session: u8,
    pub start_time: std::time::SystemTime,
    pub buffer: Vec<u8>,
    pub received_ranges: Vec<(usize, usize)>,
}

impl std::default::Default for TransportServiceCache {
    fn default() -> Self {
        Self {
            sender: NodeId(0),
            destination: Destination::Single(NodeId(0)),
            home: HomeId(0),
            session: 0,
            start_time: std::time::SystemTime::UNIX_EPOCH,
            buffer: Vec::new(),
            received_ranges: Vec::new(),
        }
    }
}

impl TransportServiceCache {
    pub fn from_first_segment(first_segment: &TransportServiceEncapsulation) -> Option<Self> {
        if first_segment.buffer.len() >= first_segment.datagram_size {
            return None;
        }

        let mut buffer = vec![0; first_segment.datagram_size];
        buffer[..first_segment.buffer.len()].copy_from_slice(first_segment.buffer.as_slice());
        let received_ranges = vec![(0, first_segment.buffer.len())];
        Some(Self {
            sender: first_segment.sender,
            destination: first_segment.destination.clone(),
            home: first_segment.home,
            session: first_segment.session,
            start_time: std::time::SystemTime::now(),
            buffer,
            received_ranges,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.received_ranges.len() == 1 && self.received_ranges[0] == (0, self.buffer.len())
    }

    pub fn append_segment(&mut self, segment: &TransportServiceEncapsulation) -> bool {
        let start = segment.datagram_offset;
        let end = segment.datagram_offset + segment.buffer.len();
        if end > self.buffer.len() {
            return false;
        }

        self.buffer[start..end].copy_from_slice(segment.buffer.as_slice());
        self.received_ranges.push((start, end));
        self.received_ranges.sort_by_key(|&(s, _)| s);
        // (3, 5) (8, 12), and then imagine if
        // 1. (3, 4) came in -> (3, 5) (8, 12)
        // 2. (3, 6) came in -> (3, 6) (8, 12)
        // 3. (3, 12) came in -> (3, 12) (8, 12) -> (3, 12)
        // 4. (9, 12) came in -> (3, 5) (8, 12)
        // 5. (5, 7) came in -> (3, 7) (8, 12)
        // 6. (6, 7) came in -> (3, 5) (6, 7), (8, 12)
        self.received_ranges.dedup_by(|next, prev| {
            if next.0 <= prev.1 {
                prev.1 = std::cmp::max(prev.1, next.1);
                true
            } else {
                false
            }
        });

        self.is_complete()
    }
}

pub struct Parser {
    pub(crate) keystore: LruKeyStore,
    transport_service_cache: [TransportServiceCache; 5],
    s0_first_segment_cache: FixedKeyValueQueue<10, u64, Vec<u8>>,
    next_transport_service_index: usize,
}

impl Parser {
    pub fn new(keystore: LruKeyStore) -> Self {
        Self {
            keystore,
            transport_service_cache: Default::default(),
            s0_first_segment_cache: Default::default(),
            next_transport_service_index: 0,
        }
    }

    /// Parses a frame from the data slice and processes passive S2 decryption.
    pub fn parse_next<'a>(&mut self, mut data: &'a [u8]) -> ParseResult<'a, Vec<Frame>> {
        let mut frames = Vec::<Frame>::new();
        loop {
            // SOF hunt: find next 0x21
            if let Some(pos) = data.iter().position(|&b| b == 0x21) {
                data = &data[pos..];
            } else {
                // No SOF in the remaining slice. Discard all remaining bytes.
                data = &data[data.len()..];
                break;
            }

            let (mut frame, rest) = match Frame::deserialize(data) {
                Ok((frame, rest)) => (frame, rest),
                Err(ParseError::Incomplete) => break,
                Err(ParseError::Invalid) | Err(ParseError::Empty) => {
                    // Skip the invalid SOF byte and hunt for the next SOF
                    data = &data[1..];
                    continue;
                }
            };

            let nsdu = match &mut frame.payload {
                FrameType::Data(nsdu) => nsdu,
                _ => {
                    // Not a data frame. Advance data and push the frame.
                    data = rest;
                    frames.push(frame);
                    continue;
                }
            };

            if nsdu.payload.is_none() || frame.channel.is_none() {
                data = rest;
                frames.push(frame);
                continue;
            }

            match nsdu.payload.as_ref().unwrap() {
                EncapsulationCommand::TransportFirstSegment(segment) => 'save_first_seg: {
                    let five_minutes_ago =
                        std::time::SystemTime::now() - std::time::Duration::from_mins(5);
                    if self.transport_service_cache.iter().any(|cached| {
                        cached.home == segment.home
                            && cached.sender == segment.sender
                            && cached.destination == segment.destination
                            && cached.session == segment.session
                            && cached.start_time > five_minutes_ago
                    }) {
                        break 'save_first_seg;
                    }

                    let cache = TransportServiceCache::from_first_segment(segment);
                    if cache.is_none() {
                        break 'save_first_seg;
                    }

                    self.transport_service_cache[self.next_transport_service_index] =
                        cache.unwrap();
                    self.transport_service_cache[self.next_transport_service_index]
                        .buffer
                        .resize(segment.datagram_size, 0);
                    self.next_transport_service_index = (self.next_transport_service_index + 1)
                        % self.transport_service_cache.len();
                }
                EncapsulationCommand::TransportSegment(segment) => 'save_segment: {
                    let five_minutes_ago =
                        std::time::SystemTime::now() - std::time::Duration::from_mins(5);
                    let cached = self.transport_service_cache.iter_mut().find(|cached| {
                        cached.home == segment.home
                            && cached.sender == segment.sender
                            && cached.destination == segment.destination
                            && cached.session == segment.session
                            && cached.start_time > five_minutes_ago
                    });
                    if cached.is_none() {
                        break 'save_segment;
                    }
                    let cached = cached.unwrap();
                    let finished = cached.append_segment(segment);
                    if finished {
                        nsdu.payload = Some(EncapsulationCommand::parse(
                            std::mem::take(&mut cached.buffer),
                            cached.sender,
                            &cached.destination,
                            cached.home,
                        ));
                        *cached = TransportServiceCache::default();
                    }
                }
                _ => {}
            }
            let mut command = nsdu.payload.take().unwrap();
            command = self.process_encap(
                nsdu.home,
                nsdu.source_node,
                &nsdu.destination,
                frame.channel.unwrap().is_long_range(),
                command,
            );
            nsdu.payload = Some(command);
            data = rest;
            frames.push(frame);
        }

        Ok((frames, data))
    }

    fn process_encap(
        &mut self,
        home: HomeId,
        sender: NodeId,
        destination: &crate::types::Destination,
        is_lr: bool,
        mut command: EncapsulationCommand,
    ) -> EncapsulationCommand {
        match &mut command {
            EncapsulationCommand::S2Nonce(nonce_report) => {
                if let crate::types::Destination::Single(receiver) = destination {
                    self.keystore
                        .cache_s2_nonce(home, sender, *receiver, nonce_report.clone());
                }
            }
            EncapsulationCommand::Security2Encrypted(encrypted, items) => {
                command = self.keystore.decrypt_s2(
                    is_lr,
                    home,
                    sender,
                    destination,
                    encrypted.clone(),
                    items,
                );
            }
            EncapsulationCommand::S0Nonce(receivers_nonce) => {
                if let crate::types::Destination::Single(receiver) = destination {
                    self.keystore
                        .cache_s0_nonce(home, *receiver, sender, receivers_nonce.clone());
                }
            }
            EncapsulationCommand::Security0Encrypted(encapsulation, payload) => {
                if let crate::types::Destination::Single(receiver) = destination
                    && let Some((decrypted_encapsulation, payload)) =
                        self.keystore
                            .decrypt_s0(home, sender, *receiver, encapsulation, payload)
                {
                    match decrypted_encapsulation.sequence_part {
                        crate::security::s0::SequencePart::First => {
                            let key = (home.0 as u64) << 32
                                | (sender.0 as u64) << 16
                                | (receiver.0 as u64) << 8
                                | decrypted_encapsulation.sequence_number.unwrap_or(0) as u64;
                            self.s0_first_segment_cache.push(key, payload.clone());
                            command = EncapsulationCommand::Security0DecryptedFirst(
                                decrypted_encapsulation,
                                payload,
                            );
                        }
                        crate::security::s0::SequencePart::Second => {
                            let key = (home.0 as u64) << 32
                                | (sender.0 as u64) << 16
                                | (receiver.0 as u64) << 8
                                | decrypted_encapsulation.sequence_number.unwrap_or(0) as u64;
                            if let Some(cached) = self.s0_first_segment_cache.get(&key) {
                                let mut first = cached.clone();
                                first.extend_from_slice(payload.as_slice());
                                command = EncapsulationCommand::Security0Decrypted(
                                    decrypted_encapsulation,
                                    Box::new(EncapsulationCommand::parse(
                                        std::mem::take(&mut first),
                                        sender,
                                        destination,
                                        home,
                                    )),
                                );
                            } else {
                                command = EncapsulationCommand::Security0DecryptedSecond(
                                    decrypted_encapsulation,
                                    payload,
                                );
                            }
                        }
                        crate::security::s0::SequencePart::Complete => {
                            command = EncapsulationCommand::Security0Decrypted(
                                decrypted_encapsulation,
                                Box::new(EncapsulationCommand::parse(
                                    payload,
                                    sender,
                                    destination,
                                    home,
                                )),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_incomplete() {
        let mut parser = Parser::new(LruKeyStore::default());
        let incomplete_data = [0x21, 0x05, 0x00];
        assert_eq!(
            parser.parse_next(&incomplete_data),
            Ok((vec![], &incomplete_data[..]))
        );
    }
    #[test]
    fn test_transfer_service_cache() {
        let first_segment = [
            0x55, 0xC0, 0x31, 0x90, 0x9F, 0x3, 0xAF, 0x1, 0x12, 0x41, 0xDB, 0xE0, 0x5C, 0x65, 0x3D,
            0x24, 0xFA, 0x1A, 0xA1, 0xAC, 0xA3, 0xD2, 0x2C, 0xCA, 0x21, 0xB9, 0xB, 0x6A, 0xF1,
            0x33, 0xF8, 0xDA, 0xD, 0x99, 0x30, 0x38, 0x65, 0x8B, 0xC4, 0xAA, 0xD8, 0x25, 0x95,
            0x93, 0xE8,
        ];
        let second_segment = [
            0x55, 0xE0, 0x31, 0x90, 0x27, 0x29, 0xF4, 0x76, 0xB0, 0x9B, 0x5A, 0x9B, 0xA4, 0x6D,
            0x74, 0xE5, 0xB3,
        ];

        let sender = NodeId(1);
        let destination = Destination::Single(NodeId(13));
        let home = HomeId(0xFDD09BC7);

        let first =
            TransportServiceEncapsulation::deserialize(&first_segment, sender, &destination, home)
                .unwrap();

        let second =
            TransportServiceEncapsulation::deserialize(&second_segment, sender, &destination, home)
                .unwrap();

        let mut cache = TransportServiceCache::from_first_segment(&first).unwrap();
        assert!(!cache.is_complete());
        assert_eq!(cache.buffer.len(), 49);

        let finished = cache.append_segment(&second);
        assert!(finished);
        assert!(cache.is_complete());
        assert_eq!(cache.buffer.len(), 49);
    }

    #[test]
    fn test_append_segment_merging() {
        let mut cache = TransportServiceCache {
            sender: NodeId(1),
            destination: Destination::Single(NodeId(2)),
            home: HomeId(123),
            session: 5,
            start_time: std::time::SystemTime::now(),
            buffer: vec![0; 12],
            received_ranges: vec![],
        };

        let make_segment = |offset: usize, len: usize| TransportServiceEncapsulation {
            sender: NodeId(1),
            destination: Destination::Single(NodeId(2)),
            home: HomeId(123),
            session: 5,
            datagram_size: 12,
            datagram_offset: offset,
            buffer: vec![0; len],
        };

        // Initialize with (3, 5) and (8, 12)
        cache.received_ranges = vec![(3, 5), (8, 12)];

        // 1. (3, 4) came in -> (3, 5) (8, 12)
        let result = cache.append_segment(&make_segment(3, 1));
        assert_eq!(cache.received_ranges, vec![(3, 5), (8, 12)]);
        assert!(!result);

        // 2. (3, 6) came in -> (3, 6) (8, 12)
        let result = cache.append_segment(&make_segment(3, 3));
        assert_eq!(cache.received_ranges, vec![(3, 6), (8, 12)]);
        assert!(!result);

        // 5. (5, 7) came in -> (3, 7) (8, 12)
        let result = cache.append_segment(&make_segment(5, 2));
        assert_eq!(cache.received_ranges, vec![(3, 7), (8, 12)]);
        assert!(!result);

        // 6. (6, 7) came in -> (3, 7) (8, 12)
        let result = cache.append_segment(&make_segment(6, 1));
        assert_eq!(cache.received_ranges, vec![(3, 7), (8, 12)]);
        assert!(!result);

        // 4. (9, 12) came in -> (3, 7) (8, 12) (no change since it's already covered by 8..12)
        let result = cache.append_segment(&make_segment(9, 3));
        assert_eq!(cache.received_ranges, vec![(3, 7), (8, 12)]);
        assert!(!result);

        // 3. (3, 12) came in -> merges both (3, 7) and (8, 12) into (3, 12)
        let result = cache.append_segment(&make_segment(3, 9));
        assert_eq!(cache.received_ranges, vec![(3, 12)]);
        assert!(!result);
        // but then (0, 3) came in
        let result = cache.append_segment(&make_segment(0, 3));
        assert!(result);
    }

    fn make_s0_encrypted_frame(
        plaintext: &[u8],
        keys: &crate::security::s0::NetworkKeyExpansion,
        sender: NodeId,
        receiver: NodeId,
        sender_nonce: &crate::security::s0::NoncePartial,
        receivers_nonce: &crate::security::s0::NoncePartial,
        nonce_requested: bool,
    ) -> Vec<u8> {
        use aes::{Aes128, Block, cipher::{BlockCipherEncrypt, KeyInit}};

        let combined_nonce = sender_nonce.to_full(receivers_nonce);

        // 1. Encrypt payload using AES-OFB
        let mut block = Block::from(combined_nonce.0);
        let encryption_key = Aes128::new_from_slice(&keys.encryption_key.0).unwrap();
        let keystream = std::iter::repeat_with(move || {
            encryption_key.encrypt_block(&mut block);
            block
        })
        .flat_map(|b| b.into_iter());

        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream)
            .map(|(p, k)| p ^ k)
            .collect();

        // 2. Calculate MAC
        let node_id_length = 1; // assuming mesh/8-bit IDs
        let auth_len = combined_nonce.0.len() + (2 * node_id_length) + 2 + ciphertext.len();
        let padding_len = (16 - (auth_len % 16)) % 16;
        let mut auth_data = Vec::with_capacity(auth_len + padding_len);
        auth_data.extend_from_slice(&combined_nonce.0);
        auth_data.push(if nonce_requested { 0xC1 } else { 0x81 });
        auth_data.push(sender.0 as u8);
        auth_data.push(receiver.0 as u8);
        auth_data.push(ciphertext.len() as u8);
        auth_data.extend_from_slice(&ciphertext);
        auth_data.extend(std::iter::repeat_n(0, padding_len));

        let authentication_key = Aes128::new_from_slice(&keys.authentication_key.0).unwrap();
        let final_state = auth_data
            .chunks_exact(16)
            .fold([0u8; 16], |mut state, chunk| {
                state
                    .iter_mut()
                    .zip(chunk.iter())
                    .for_each(|(sb, cb)| *sb ^= cb);
                let mut b = Block::from(state);
                authentication_key.encrypt_block(&mut b);
                b.into()
            });
        let mac: [u8; 8] = final_state[..8].try_into().unwrap();

        // 3. Serialize
        let mut data = Vec::new();
        data.push(0x98);
        data.push(if nonce_requested { 0xC1 } else { 0x81 });
        data.extend_from_slice(&sender_nonce.0);
        data.extend_from_slice(&ciphertext);
        data.push(receivers_nonce.0[0]); // receivers_nonce_id
        data.extend_from_slice(&mac);
        data
    }

    #[test]
    fn test_parser_s0_decryption() {
        use crate::security::Key;
        use crate::keys::KeyRing;

        let mut keystore = LruKeyStore::default();
        let home = HomeId(0xfdd09bc7);
        let sender = NodeId(1);
        let receiver = NodeId(0xF);

        // 1. Configure network keyring with the S0 key
        let network_key = Key(hex_literal::hex!("F9146ECC78D0036F1A4C9F55141C8989"));
        let keyring = KeyRing::new(Some(network_key), None, None, None, None, None);
        keystore.insert_keyring(home, keyring);

        // 2. Cache the S0 receiver's partial nonce
        let nonce_report_bytes = hex_literal::hex!("988041C9DDA4DE802A37");
        let receivers_nonce = crate::security::s0::NoncePartial(
            nonce_report_bytes[2..].try_into().unwrap(),
        );
        keystore.cache_s0_nonce(home, sender, receiver, receivers_nonce);

        let mut parser = Parser::new(keystore);

        // 3. Process the S0 Encrypted frame
        let encrypted_frame_bytes = hex_literal::hex!(
            "9881CBC621CCAE827E1F7C7F408AC09F1D8BD0B35A9641729714507C170DA3"
        );
        let command = EncapsulationCommand::parse(
            encrypted_frame_bytes.to_vec(),
            sender,
            &Destination::Single(receiver),
            home,
        );

        let processed = parser.process_encap(
            home,
            sender,
            &Destination::Single(receiver),
            false,
            command,
        );

        // Verify it decrypted to Security0Decrypted
        match processed {
            EncapsulationCommand::Security0Decrypted(decrypted_info, inner_cmd) => {
                assert!(!decrypted_info.nonce_requested);
                assert_eq!(decrypted_info.sequence_number, None);
                assert_eq!(decrypted_info.receivers_nonce, 0x41);

                match *inner_cmd {
                    EncapsulationCommand::Unencapsulated(payload) => {
                        let expected_payload = hex_literal::hex!("6c018207630b0100000000");
                        assert_eq!(payload, expected_payload);
                    }
                    _ => panic!("Expected Unencapsulated inner command"),
                }
            }
            _ => panic!("Expected Security0Decrypted, got {:?}", processed),
        }
    }

    #[test]
    fn test_parser_s0_fragmented_assembly() {
        use crate::security::Key;
        use crate::keys::KeyRing;

        let mut keystore = LruKeyStore::default();
        let home = HomeId(0xfdd09bc7);
        let sender = NodeId(1);
        let receiver = NodeId(0xF);

        // Configure keyring and cache nonces
        let network_key = Key(hex_literal::hex!("F9146ECC78D0036F1A4C9F55141C8989"));
        let keys = crate::security::s0::NetworkKeyExpansion::new(&network_key);
        let keyring = KeyRing::new(Some(network_key), None, None, None, None, None);
        keystore.insert_keyring(home, keyring);

        let sender_nonce_1 = crate::security::s0::NoncePartial([0xAA; 8]);
        let sender_nonce_2 = crate::security::s0::NoncePartial([0xBB; 8]);
        let receivers_nonce = crate::security::s0::NoncePartial([0x41; 8]);
        keystore.cache_s0_nonce(home, sender, receiver, receivers_nonce.clone());

        let mut parser = Parser::new(keystore);

        let seq_num = 5u8;
        let first_control_byte = 0b0001_0000 | seq_num; // 0x15
        let second_control_byte = 0b0011_0000 | seq_num; // 0x35

        let mut first_plaintext = vec![first_control_byte];
        first_plaintext.extend_from_slice(&[0x01, 0x02, 0x03]);

        let mut second_plaintext = vec![second_control_byte];
        second_plaintext.extend_from_slice(&[0x04, 0x05]);

        let first_frame_bytes = make_s0_encrypted_frame(
            &first_plaintext,
            &keys,
            sender,
            receiver,
            &sender_nonce_1,
            &receivers_nonce,
            false,
        );

        let second_frame_bytes = make_s0_encrypted_frame(
            &second_plaintext,
            &keys,
            sender,
            receiver,
            &sender_nonce_2,
            &receivers_nonce,
            false,
        );

        let cmd_1 = EncapsulationCommand::parse(
            first_frame_bytes,
            sender,
            &Destination::Single(receiver),
            home,
        );
        let res_1 = parser.process_encap(home, sender, &Destination::Single(receiver), false, cmd_1);

        match res_1 {
            EncapsulationCommand::Security0DecryptedFirst(dec, payload) => {
                assert_eq!(dec.sequence_number, Some(seq_num));
                assert_eq!(dec.sequence_part, crate::security::s0::SequencePart::First);
                assert_eq!(payload, vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("Expected Security0DecryptedFirst, got {:?}", res_1),
        }

        let cmd_2 = EncapsulationCommand::parse(
            second_frame_bytes,
            sender,
            &Destination::Single(receiver),
            home,
        );
        let res_2 = parser.process_encap(home, sender, &Destination::Single(receiver), false, cmd_2);

        match res_2 {
            EncapsulationCommand::Security0Decrypted(dec, inner_cmd) => {
                assert_eq!(dec.sequence_number, Some(seq_num));
                assert_eq!(dec.sequence_part, crate::security::s0::SequencePart::Second);
                match *inner_cmd {
                    EncapsulationCommand::Unencapsulated(full_payload) => {
                        assert_eq!(full_payload, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
                    }
                    _ => panic!("Expected inner command to be Unencapsulated"),
                }
            }
            _ => panic!("Expected Security0Decrypted, got {:?}", res_2),
        }
    }
}

