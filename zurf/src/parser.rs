// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::frame::{Frame, FrameType};
use crate::keys::KeyStore;
use crate::mpdu::EncapsulationCommand;
use crate::security::s2::SpanState;
use crate::types::Destination;
use crate::types::{ParseError, ParseResult};

pub struct Parser {
    pub keystore: KeyStore,
}

impl Parser {
    pub fn new(keystore: KeyStore) -> Self {
        Self { keystore }
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

            if let Some(EncapsulationCommand::S2Nonce(receivers_nonce)) = &nsdu.payload {
                self.keystore.insert_receiver_entropy(
                    &nsdu.home_id,
                    &nsdu.source_node_id,
                    receivers_nonce.entropy.clone(),
                    receivers_nonce.sequence_number,
                );
            } else if let Some(EncapsulationCommand::Security2Encrypted(
                encrypted_message,
                ciphertext,
            )) = &nsdu.payload
            {
                let destination_node_id = match nsdu.destination {
                    Destination::Single(node_id) => node_id,
                    _ => {
                        // TODO MPAN handling
                        data = rest;
                        frames.push(frame);
                        continue;
                    }
                };

                let mut decrypted_payload = None;

                if let Some(senders_entropy) = &encrypted_message.senders_entropy {
                    if let Some((receivers_entropy, receivers_sequence_number)) = self
                        .keystore
                        .get_receiver_entropy(&nsdu.home_id, &destination_node_id)
                        && let Some(keyring) = self.keystore.get_keyring(&nsdu.home_id)
                    {
                        let is_lr = frame.channel.map(|c| c.is_long_range()).unwrap_or(false);
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
                        let span_decryption = candidate_classes
                            .iter()
                            .filter_map(|class| {
                                keyring[*class].as_ref().map(|expansion| (class, expansion))
                            })
                            .find_map(|(&class, key_expansion)| {
                                SpanState::new(
                                    mixed_entropy.clone(),
                                    key_expansion,
                                    class,
                                    encrypted_message.sequence_number,
                                    receivers_sequence_number,
                                    encrypted_message.aad.clone(),
                                    ciphertext,
                                )
                            });

                        if let Some((span_state, decrypted)) = span_decryption {
                            self.keystore.insert_span(
                                &nsdu.home_id,
                                &nsdu.source_node_id,
                                &destination_node_id,
                                span_state.clone(),
                            );
                            decrypted_payload = Some(decrypted);
                        }
                    }
                } else {
                    let keyring = match self.keystore.get_keyring(&nsdu.home_id) {
                        Some(kr) => kr,
                        None => {
                            data = rest;
                            frames.push(frame);
                            continue;
                        }
                    };
                    let span = match self.keystore.get_span(
                        &nsdu.home_id,
                        &nsdu.source_node_id,
                        &destination_node_id,
                    ) {
                        Some(span) => span,
                        _ => {
                            data = rest;
                            frames.push(frame);
                            continue;
                        }
                    };

                    if let Some(key_expansion) = &keyring[span.security_class]
                        && let Ok(plaintext) = span.decrypt_s2_frame(
                            key_expansion,
                            encrypted_message.sequence_number,
                            encrypted_message.aad.clone(),
                            ciphertext,
                        )
                    {
                        decrypted_payload = Some(plaintext);
                    }
                }

                if let Some(plaintext) = decrypted_payload {
                    let inner_cmd = EncapsulationCommand::parse(
                        &plaintext,
                        &nsdu.source_node_id,
                        &nsdu.destination,
                        &nsdu.home_id,
                    );
                    nsdu.payload = Some(EncapsulationCommand::Security2Decrypted(
                        encrypted_message.clone(),
                        Box::new(inner_cmd),
                    ));
                }
            };

            data = rest;
            frames.push(frame);
        }

        Ok((frames, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_incomplete() {
        let mut parser = Parser::new(KeyStore::default());
        let incomplete_data = [0x21, 0x05, 0x00];
        assert_eq!(
            parser.parse_next(&incomplete_data),
            Ok((vec![], &incomplete_data[..]))
        );
    }

    #[test]
    fn test_parser_s2_decryption() {
        use crate::keys::KeyRing;
        use crate::security::{Key, s2::PartialEntropyInput};
        use crate::types::{HomeId, NodeId};

        let permanent_network_key = Key::new(hex_literal::hex!("e0ff431eb430fa03c85f519adc3aa518"));
        let public_entropy =
            PartialEntropyInput::new(hex_literal::hex!("2fb9b45a6d0a12b789cbc1ce4f2e0b51"));

        let mut keystore = KeyStore::default();
        keystore.insert_receiver_entropy(&HomeId(0xfdd09bc7), &NodeId(1), public_entropy, 0);

        let keyring = KeyRing::new(Some(permanent_network_key), None, None, None, None);
        keystore.insert_keyring(HomeId(0xfdd09bc7), keyring);

        let mut parser = Parser::new(keystore);

        let mut raw_frame = vec![
            0x21, // SOF
            0x01, // FrameType::Data
            0x00, 0x00, // Timestamp
            0x21, // channel_speed (Mesh2, Mesh40k)
            0x00, // region
            0x00, // rssi
            0x21, 0x03, // start_of_data_marker
            0x35, // len of MPDU (53 bytes)
        ];

        // 53 bytes of MPDU
        raw_frame.extend_from_slice(&[0xFD, 0xD0, 0x9B, 0xC7]); // Home ID
        raw_frame.push(0x02); // Sender Node ID
        raw_frame.extend_from_slice(&[0x01, 0x00]); // Frame Control (Singlecast, seq=0)
        raw_frame.push(0x35); // MPDU Length byte
        raw_frame.push(0x01); // Destination Node ID

        // S2 Payload (43 bytes): 0x9F, 0x03, S2 Header (20 bytes), Ciphertext (21 bytes)
        raw_frame.extend_from_slice(&[0x9F, 0x03]);
        raw_frame.extend_from_slice(&hex_literal::hex!(
            "7d 01 12 41 63 4f 03 d2 40 7d f9 d6 b2 11 95 ce 68 87 eb 71"
        ));
        raw_frame.extend_from_slice(&hex_literal::hex!(
            "93 16 48 dc 81 41 11 d4 c4 dc be 47 a9 42 db ac 58 6a 35 e0 2a"
        ));

        raw_frame.push(0x00); // Dummy XOR Checksum byte for Mesh40k

        let parse_result = parser.parse_next(&raw_frame);
        assert!(parse_result.is_ok());

        let (frames, rest) = parse_result.unwrap();
        assert_eq!(frames.len(), 1);
        assert!(rest.is_empty());

        // Verify the SpanState was successfully saved in the keystore
        let span = parser
            .keystore
            .get_span(&HomeId(0xfdd09bc7), &NodeId(2), &NodeId(1))
            .unwrap()
            .clone();
        assert_eq!(span.original_sender_sequence_number, 0x7D);
        assert_eq!(
            span.security_class,
            crate::keys::SecurityClass::Unauthenticated
        );

        // Generate the second frame using the updated DRBG state and CCM key
        let keyring = parser.keystore.get_keyring(&HomeId(0xfdd09bc7)).unwrap();
        let key_expansion = keyring[span.security_class].as_ref().unwrap();

        let mut second_drbg = span.drbg.clone();
        let second_nonce: [u8; 13] = second_drbg.generate(); // 2nd nonce (since DRBG is already advanced to step 1)

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

        let mut raw_frame_2 = vec![
            0x21, // SOF
            0x01, // FrameType::Data
            0x00,
            0x00, // Timestamp
            0x21, // channel_speed
            0x00, // region
            0x00, // rssi
            0x21,
            0x03,                        // start_of_data_marker
            (10 + total_s2_len_2) as u8, // len of MPDU
        ];

        raw_frame_2.extend_from_slice(&[0xFD, 0xD0, 0x9B, 0xC7]); // Home ID
        raw_frame_2.push(0x02); // Sender Node ID
        raw_frame_2.extend_from_slice(&[0x01, 0x00]); // Frame Control
        raw_frame_2.push((10 + total_s2_len_2) as u8); // MPDU Length
        raw_frame_2.push(0x01); // Destination Node ID

        raw_frame_2.extend_from_slice(&[0x9F, 0x03]);
        raw_frame_2.extend_from_slice(&s2_header_2);
        raw_frame_2.extend_from_slice(&ciphertext_2);
        raw_frame_2.push(0x00); // Dummy CRC

        let parse_result_2 = parser.parse_next(&raw_frame_2);
        assert!(parse_result_2.is_ok());
        let (frames_2, rest_2) = parse_result_2.unwrap();
        assert_eq!(frames_2.len(), 1);
        assert!(rest_2.is_empty());

        let span_after = parser
            .keystore
            .get_span(&HomeId(0xfdd09bc7), &NodeId(2), &NodeId(1))
            .unwrap();
        assert_eq!(span_after.original_sender_sequence_number, 0x7E);
    }
}
