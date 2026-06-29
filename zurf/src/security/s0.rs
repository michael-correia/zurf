// SPDX-License-Identifier: LGPL-3.0-or-later

use aes::{Aes128, Block, cipher::BlockCipherEncrypt};
use ccm::{
    Ccm, KeyInit,
    consts::{U8, U13},
};

use crate::types::NodeId;

pub type Aes128Ccm = Ccm<Aes128, U8, U13>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkKeyExpansion {
    pub encryption_key: crate::security::Key,
    pub authentication_key: crate::security::Key,
}

impl NetworkKeyExpansion {
    pub fn new(network_key: &crate::security::Key) -> NetworkKeyExpansion {
        let cipher = Aes128::new_from_slice(&network_key.0).unwrap();

        const ENC_INIT: [u8; 16] = [0xAA; 16];
        let mut encryption_key = Block::from(ENC_INIT);
        cipher.encrypt_block(&mut encryption_key);
        let encryption_key = crate::security::Key(encryption_key.0);

        const AUTH_INIT: [u8; 16] = [0x55; 16];
        let mut authentication_key = Block::from(AUTH_INIT);
        cipher.encrypt_block(&mut authentication_key);
        let authentication_key = crate::security::Key(authentication_key.0);

        Self {
            encryption_key,
            authentication_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoncePartial([u8; 8]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceFull([u8; 16]);

impl NoncePartial {
    pub fn to_full(&self, nonce_partial: &NoncePartial) -> NonceFull {
        NonceFull(std::array::from_fn(|i| {
            if i < self.0.len() {
                self.0[i]
            } else {
                nonce_partial.0[i - self.0.len()]
            }
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAuthenticationCode([u8; 8]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEncapsulation {
    pub nonce_requested: bool,
    pub sender_nonce: NoncePartial,
    pub receivers_nonce_id: u8,
    pub mac: MessageAuthenticationCode,
}

impl EncryptedEncapsulation {
    pub fn deserialize(data: &[u8]) -> Option<(Self, Vec<u8>)> {
        let (header, data) = data.split_at_checked(2)?;

        if header != [0x98, 0x81] && header != [0x98, 0xC1] {
            return None;
        }

        let nonce_requested = header == [0x98, 0xC1];

        let (sender_nonce, data) = data.split_at_checked(8)?;
        let sender_nonce = NoncePartial(sender_nonce.try_into().unwrap());

        let receivers_nonce_start = data.len().checked_sub(9)?;

        let (data, receivers_nonce_start) = data.split_at_checked(receivers_nonce_start)?;
        let receivers_nonce_id = receivers_nonce_start[0];
        let mac = MessageAuthenticationCode(receivers_nonce_start[1..].try_into().unwrap());
        let payload = data.to_vec();

        Some((
            Self {
                nonce_requested,
                sender_nonce,
                receivers_nonce_id,
                mac,
            },
            payload,
        ))
    }

    fn verify_mac(
        &self,
        payload: &[u8],
        keys: &NetworkKeyExpansion,
        sender: NodeId,
        receiver: NodeId,
        combined_nonce: &NonceFull,
    ) -> bool {
        // S0 only works with mesh, but I see no reason to add that restriction to the zniffer
        let node_id_length = if receiver.0 > 255 || sender.0 > 255 {
            2
        } else {
            1
        };

        // One for header type, one for payload length
        let auth_len = combined_nonce.0.len() + (2 * node_id_length) + 2 + payload.len();
        let padding_len = (16 - (auth_len % 16)) % 16;
        let mut auth_data = Vec::with_capacity(auth_len + padding_len);
        auth_data.extend_from_slice(&combined_nonce.0);
        auth_data.push(if self.nonce_requested { 0xC1 } else { 0x81 });
        if node_id_length == 2 {
            auth_data.push((sender.0 >> 8) as u8);
        }
        auth_data.push((sender.0 & 0xFF) as u8);
        if node_id_length == 2 {
            auth_data.push((receiver.0 >> 8) as u8);
        }
        auth_data.push((receiver.0 & 0xFF) as u8);

        auth_data.push(payload.len() as u8);
        auth_data.extend_from_slice(payload);
        auth_data.extend(std::iter::repeat_n(0, padding_len));

        // CBC-MAC calculation
        let authentication_key = Aes128::new_from_slice(&keys.authentication_key.0).unwrap();
        let final_state = auth_data
            .chunks_exact(16)
            .fold([0u8; 16], |mut state, chunk| {
                state
                    .iter_mut()
                    .zip(chunk.iter())
                    .for_each(|(state_byte, chunk_byte)| *state_byte ^= chunk_byte);

                let mut block = Block::from(state);
                authentication_key.encrypt_block(&mut block);
                block.into()
            });
        let calculated_mac: [u8; 8] = final_state[..8].try_into().unwrap();
        calculated_mac == self.mac.0
    }

    fn decrypt_s0_frame(
        &self,
        payload: &[u8],
        keys: &NetworkKeyExpansion,
        sender: NodeId,
        receiver: NodeId,
        receivers_nonce: &NoncePartial,
    ) -> Result<Vec<u8>, ccm::aead::Error> {
        let combined_nonce = self.sender_nonce.to_full(receivers_nonce);
        if !self.verify_mac(payload, keys, sender, receiver, &combined_nonce) {
            return Err(ccm::aead::Error);
        }

        let mut block = Block::from(combined_nonce.0);
        let encryption_key = Aes128::new_from_slice(&keys.encryption_key.0).unwrap();
        let keystream_bytes = std::iter::repeat_with(move || {
            encryption_key.encrypt_block(&mut block);
            block
        })
        .flat_map(|b| b.into_iter());

        Ok(payload
            .iter()
            .zip(keystream_bytes)
            .map(|(cipher_byte, key_byte)| cipher_byte ^ key_byte)
            .collect::<Vec<u8>>())
    }

    pub fn decrypt(
        &self,
        payload: &[u8],
        keys: &NetworkKeyExpansion,
        sender: NodeId,
        receiver: NodeId,
        receivers_nonce: &NoncePartial,
    ) -> Result<(DecryptedEncapsulation, Vec<u8>), ccm::aead::Error> {
        let plaintext = self.decrypt_s0_frame(payload, keys, sender, receiver, receivers_nonce)?;
        if plaintext.len() < 2 {
            return Err(ccm::aead::Error);
        }
        let sequence_part = match plaintext[0] & 0b0011_0000 {
            0b0001_0000 => SequencePart::First,
            0b0011_0000 => SequencePart::Second,
            _ => SequencePart::Complete,
        };
        let sequence_number = if sequence_part == SequencePart::Complete {
            None
        } else {
            Some(plaintext[0] & 0b0000_1111)
        };
        Ok((
            DecryptedEncapsulation {
                nonce_requested: self.nonce_requested,
                sequence_number,
                sequence_part,
                receivers_nonce: self.receivers_nonce_id,
            },
            plaintext[1..].to_vec(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencePart {
    First,
    Second,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedEncapsulation {
    pub nonce_requested: bool,
    pub sequence_number: Option<u8>,
    pub sequence_part: SequencePart,
    pub receivers_nonce: u8,
}

// ==========================================
// Tests
// ==========================================

#[cfg(test)]
mod tests {
    use crate::security::Key;

    use super::*;

    #[test]
    fn test_decrypt_success() {
        let keys =
            NetworkKeyExpansion::new(&Key(hex_literal::hex!("F9146ECC78D0036F1A4C9F55141C8989")));
        const NONCE_REPORT: [u8; 10] = hex_literal::hex!("988041C9DDA4DE802A37");
        let security_encapsulation_nonce_get =
            hex_literal::hex!("9881CBC621CCAE827E1F7C7F408AC09F1D8BD0B35A9641729714507C170DA3");
        let receivers_nonce: [u8; 8] = NONCE_REPORT[2..].try_into().unwrap();
        let (parsed_encapsulation, payload) =
            EncryptedEncapsulation::deserialize(&security_encapsulation_nonce_get).unwrap();

        let (decrypted_info, payload) = parsed_encapsulation
            .decrypt(
                &payload,
                &keys,
                NodeId(1),
                NodeId(0xF),
                &NoncePartial(receivers_nonce),
            )
            .unwrap();

        assert!(!decrypted_info.nonce_requested);
        assert_eq!(decrypted_info.sequence_number, None);
        assert_eq!(decrypted_info.sequence_part, SequencePart::Complete);
        assert_eq!(decrypted_info.receivers_nonce, 0x41);

        let expected_payload = hex_literal::hex!("6c018207630b0100000000");
        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_decrypt_invalid_mac() {
        let keys =
            NetworkKeyExpansion::new(&Key(hex_literal::hex!("F9146ECC78D0036F1A4C9F55141C8989")));
        const NONCE_REPORT: [u8; 10] = hex_literal::hex!("988041C9DDA4DE802A37");
        let mut security_encapsulation_nonce_get =
            hex_literal::hex!("9881CBC621CCAE827E1F7C7F408AC09F1D8BD0B35A9641729714507C170DA3");

        // Corrupt the MAC signature to ensure verification fails
        let last_idx = security_encapsulation_nonce_get.len() - 1;
        security_encapsulation_nonce_get[last_idx] ^= 0xFF;

        let receivers_nonce: [u8; 8] = NONCE_REPORT[2..].try_into().unwrap();
        let (parsed_encapsulation, payload) =
            EncryptedEncapsulation::deserialize(&security_encapsulation_nonce_get).unwrap();

        let result = parsed_encapsulation.decrypt(
            &payload,
            &keys,
            NodeId(1),
            NodeId(0xF),
            &NoncePartial(receivers_nonce),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_payload() {
        let keys =
            NetworkKeyExpansion::new(&Key(hex_literal::hex!("F9146ECC78D0036F1A4C9F55141C8989")));
        let receivers_nonce = [0x41; 8];
        let sender_nonce = NoncePartial([0x12; 8]);
        let payload = vec![0x00]; // 1-byte payload (too short)

        // Build auth data manually to calculate a valid MAC signature
        let mut auth_data = Vec::with_capacity(8 + 8 + 4 + 1);
        auth_data.extend_from_slice(&sender_nonce.0);
        auth_data.extend_from_slice(&receivers_nonce);
        auth_data.push(0x81);
        auth_data.push(1); // source
        auth_data.push(0xF); // dest
        auth_data.push(1); // payload length
        auth_data.extend_from_slice(&payload);

        let padding_len = (16 - (auth_data.len() % 16)) % 16;
        auth_data.extend(std::iter::repeat_n(0, padding_len));

        let authentication_key = Aes128::new_from_slice(&keys.authentication_key.0).unwrap();
        let mut state = [0u8; 16];
        for chunk in auth_data.chunks_exact(16) {
            for i in 0..16 {
                state[i] ^= chunk[i];
            }
            let mut block = Block::from(state);
            authentication_key.encrypt_block(&mut block);
            state.copy_from_slice(block.as_slice());
        }
        let calculated_mac = MessageAuthenticationCode(state[..8].try_into().unwrap());

        let enc = EncryptedEncapsulation {
            nonce_requested: false,
            sender_nonce,
            receivers_nonce_id: 0x41,
            mac: calculated_mac,
        };

        let result = enc.decrypt(
            &payload,
            &keys,
            NodeId(1),
            NodeId(0xF),
            &NoncePartial(receivers_nonce),
        );
        assert!(result.is_err());
    }
}
