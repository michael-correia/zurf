// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::keys::SecurityClass;
use crate::security::Key;
use crate::types::{HomeId, NodeId};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes128Enc, Block};
use ccm::aead::{Aead, Payload};
use ccm::{
    Ccm,
    consts::{U8, U13},
};
use cmac::{Cmac, Mac};

pub type Aes128Ccm = Ccm<Aes128, U8, U13>;

// ==========================================
// Key Expansion & Entropy
// ==========================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonalizationString([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkKeyExpansion {
    pub ccm_key: Key,
    pub mpan_key: Key,
    pub personalization_string: PersonalizationString,
}

impl NetworkKeyExpansion {
    pub fn new(network_key: &Key) -> NetworkKeyExpansion {
        const SALT: [u8; 15] = [0x55u8; 15];
        let mut mac = Cmac::<Aes128>::new_from_slice(&network_key.0).unwrap();
        mac.update(&SALT);
        mac.update(&[0x01]);
        let t1 = mac.finalize_reset().into_bytes();

        mac.update(&t1);
        mac.update(&SALT);
        mac.update(&[0x02]);
        let t2 = mac.finalize_reset().into_bytes();

        mac.update(&t2);
        mac.update(&SALT);
        mac.update(&[0x03]);
        let t3 = mac.finalize_reset().into_bytes();

        mac.update(&t3);
        mac.update(&SALT);
        mac.update(&[0x04]);
        let t4 = mac.finalize().into_bytes();

        Self {
            ccm_key: Key(t1.0),
            mpan_key: Key(t4.0),
            personalization_string: PersonalizationString(unsafe {
                std::mem::transmute::<[[u8; 16]; 2], [u8; 32]>([t2.0, t3.0])
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialEntropyInput {
    entropy: [u8; 16],
}

impl PartialEntropyInput {
    pub fn new(entropy: [u8; 16]) -> Self {
        Self { entropy }
    }

    fn derive_entropy(pseudo_random_key: [u8; 16]) -> DerivedEntropy {
        const ENTROPY_INPUT: [u8; 15] = [0x88u8; 15];
        let mut mac = Cmac::<Aes128>::new_from_slice(&pseudo_random_key).unwrap();
        mac.update(&ENTROPY_INPUT);
        mac.update(&[0x00]);
        mac.update(&ENTROPY_INPUT);
        mac.update(&[0x01]);
        let t1 = mac.finalize_reset().into_bytes();

        mac.update(&t1);
        mac.update(&ENTROPY_INPUT);
        mac.update(&[0x02]);

        let t2 = mac.finalize().into_bytes();

        let output: [u8; 32] = unsafe { std::mem::transmute([t1.0, t2.0]) };
        DerivedEntropy(output)
    }

    pub fn with_senders_entropy(&self, sender: &PartialEntropyInput) -> DerivedEntropy {
        const NONCE: [u8; 16] = [0x26u8; 16];
        let mut nonce_prk = Cmac::<Aes128>::new_from_slice(&NONCE).unwrap();
        nonce_prk.update(&sender.entropy);
        nonce_prk.update(&self.entropy);
        Self::derive_entropy(nonce_prk.finalize().into_bytes().0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedEntropy([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DrbgCount([u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrDrbg {
    key: Key,
    value: DrbgCount,
}

impl CtrDrbg {
    fn increment<const N: usize>(&mut self) -> [u8; N] {
        let mut temp = [0u8; N];
        let mut offset = 0;
        let cipher = Aes128Enc::new_from_slice(&self.key.0).unwrap();
        while offset < N {
            self.value.0 = u128::from_be_bytes(self.value.0)
                .wrapping_add(1)
                .to_be_bytes();
            let mut block = Block::from(self.value.0);
            cipher.encrypt_block(&mut block);
            let len_to_copy = std::cmp::min(16, N - offset);
            temp[offset..offset + len_to_copy].copy_from_slice(&block.0[0..len_to_copy]);
            offset += 16;
        }
        temp
    }

    fn update(&mut self, seed_material: [u8; 32]) {
        let temp: [u8; 32] = self.increment();
        self.key.0 = std::array::from_fn(|i| seed_material[i] ^ temp[i]);
        self.value.0 = std::array::from_fn(|i| seed_material[i + 16] ^ temp[i + 16]);
    }

    pub fn new(entropy: &DerivedEntropy, personalization_string: &PersonalizationString) -> Self {
        let seed_material: [u8; 32] =
            std::array::from_fn(|i| entropy.0[i] ^ personalization_string.0[i]);

        let mut drbg = Self {
            key: Key([0u8; 16]),
            value: DrbgCount([0u8; 16]),
        };

        drbg.update(seed_material);
        drbg
    }

    pub fn generate<const N: usize>(&mut self) -> [u8; N] {
        let temp = self.increment();
        self.update([0u8; 32]);
        temp
    }
}

// ==========================================
// Protocol States
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanState {
    drbg: CtrDrbg,
    pub security_class: SecurityClass,
    original_sender: NodeId,
    original_sender_sequence_number: u8,
    original_receiver_sequence_number: u8,
    original_receiver: NodeId,
    laggy_sequence_number: u8,
}

impl SpanState {
    pub fn decrypt_s2_frame(
        &mut self,
        nk_expansion: &NetworkKeyExpansion,
        sequence_number: u8,
        aad: &AdditionalAuthenticatedData,
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, ccm::aead::Error> {
        let mut drbg = self.drbg.clone();

        let original_sender = aad.sender == self.original_sender;

        let diff = if original_sender {
            sequence_number.wrapping_sub(self.original_sender_sequence_number)
        } else {
            sequence_number.wrapping_sub(self.original_receiver_sequence_number)
        };

        let laggy_diff = self
            .original_sender_sequence_number
            .wrapping_add(self.original_receiver_sequence_number)
            .wrapping_sub(self.laggy_sequence_number);

        let diff = (diff as u16) + (laggy_diff as u16);

        if diff == 0 || diff > 25 {
            return Err(ccm::aead::Error);
        }

        let mut iterations: u16;
        //drbg.generate::<13>();
        for i in 0..diff {
            iterations = i;
            let nonce: [u8; 13] = drbg.generate();

            let cipher = Aes128Ccm::new(&nk_expansion.ccm_key.0.into());
            let aad_bytes = aad.into_be_bytes();
            let payload = Payload {
                msg: ciphertext_with_tag,
                aad: &aad_bytes,
            };
            let res = cipher.decrypt(&nonce.into(), payload);
            if res.is_ok() {
                for _ in 0..iterations.saturating_sub(15) {
                    self.drbg.generate::<13>();
                    self.laggy_sequence_number = self.laggy_sequence_number.wrapping_add(1);
                }
                if original_sender {
                    self.original_sender_sequence_number = sequence_number;
                } else {
                    self.original_receiver_sequence_number = sequence_number
                }
                return res;
            }
        }
        Err(ccm::aead::Error)
    }

    pub fn new(
        entropy: &DerivedEntropy,
        nk_expansion: &NetworkKeyExpansion,
        security_class: SecurityClass,
        sender_sequence_number: u8,
        receiver_sequence_number: u8,
        aad: &AdditionalAuthenticatedData,
        ciphertext_with_tag: &[u8],
    ) -> Option<(Self, Vec<u8>)> {
        let mut state = Self {
            drbg: CtrDrbg::new(entropy, &nk_expansion.personalization_string),
            security_class,
            original_sender_sequence_number: sender_sequence_number.wrapping_sub(1),
            original_sender: aad.sender,
            original_receiver: match aad.destination {
                Destination::Singlecast(node) => node,
                _ => {
                    return None;
                }
            },
            original_receiver_sequence_number: receiver_sequence_number,
            laggy_sequence_number: receiver_sequence_number
                .wrapping_add(sender_sequence_number.wrapping_sub(1)),
        };
        let output = state.decrypt_s2_frame(
            nk_expansion,
            sender_sequence_number,
            aad,
            ciphertext_with_tag,
        );
        match output {
            Ok(output) => Some((state, output)),
            Err(_) => None,
        }
    }

    #[cfg(test)]
    pub fn get_drbg(&self) -> &CtrDrbg {
        &self.drbg
    }

    #[cfg(test)]
    pub fn get_original_sender_sequence_number(&self) -> u8 {
        self.original_sender_sequence_number
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpanState {
    inner_state: [u8; 16],
    pub security_class: SecurityClass,
}

impl std::default::Default for MpanState {
    fn default() -> Self {
        Self {
            inner_state: [0; 16],
            security_class: SecurityClass::Unauthenticated,
        }
    }
}

impl MpanState {
    pub fn new(inner_state: [u8; 16], security_class: SecurityClass) -> Self {
        Self {
            inner_state,
            security_class,
        }
    }

    pub fn decrypt_s2_frame(
        &mut self,
        nk_expansion: &NetworkKeyExpansion,
        aad: AdditionalAuthenticatedData,
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, ccm::aead::Error> {
        let cipher_ecb = Aes128Enc::new_from_slice(&nk_expansion.mpan_key.0).unwrap();
        let mut result: Result<Vec<u8>, ccm::aead::Error> = Err(ccm::aead::Error);
        let cipher_ccm = Aes128Ccm::new(&nk_expansion.ccm_key.0.into());
        let aad_bytes = aad.into_be_bytes();
        let mut temp_inner_state = self.inner_state;

        for i in 0..255 {
            let mut block = Block::from(temp_inner_state);
            temp_inner_state = u128::from_be_bytes(temp_inner_state)
                .wrapping_add(1)
                .to_be_bytes();
            cipher_ecb.encrypt_block(&mut block);
            let nonce: [u8; 13] = block.0[..13].try_into().unwrap();

            let payload = Payload {
                msg: ciphertext_with_tag,
                aad: &aad_bytes,
            };
            result = cipher_ccm.decrypt(&nonce.into(), payload);
            if result.is_ok() {
                if i >= 15 {
                    self.inner_state = u128::from_be_bytes(self.inner_state)
                        .wrapping_add(i - 15)
                        .to_be_bytes();
                }
                break;
            }
        }
        result
    }
}

// ==========================================
// Frame Parsing, AAD, and Encapsulation
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Singlecast(NodeId),
    Multicast(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalAuthenticatedData {
    pub sender: NodeId,
    pub destination: Destination,
    pub home: HomeId,
    pub nsdu_length: u16,
    pub unencrypted: Vec<u8>,
}

impl AdditionalAuthenticatedData {
    pub fn into_be_bytes(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::with_capacity(10 + self.unencrypted.len());
        let dest_val = match self.destination {
            Destination::Singlecast(node) => node.0,
            Destination::Multicast(group) => group as u16,
        };
        // Determine if we need to use the 2-byte AAD layout (CC:009F.01.00.11.00A)
        let use_2_bytes = self.sender.0 > 255 || dest_val > 255;

        if use_2_bytes {
            data.extend(u16::to_be_bytes(self.sender.0));
            data.extend(u16::to_be_bytes(dest_val));
        } else {
            data.push(self.sender.0 as u8);
            data.push(dest_val as u8);
        }
        data.extend(u32::to_be_bytes(self.home.0));
        data.extend(u16::to_be_bytes(self.nsdu_length));
        data.extend_from_slice(self.unencrypted.as_slice());
        data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEncapsulation {
    pub sequence_number: u8,
    pub extensions: Option<Vec<Extension>>,
    pub has_encrypted_extensions: bool,
    pub aad: AdditionalAuthenticatedData,
}

impl EncryptedEncapsulation {
    pub fn get_senders_entropy(&self) -> Option<&PartialEntropyInput> {
        if let Some(extensions) = &self.extensions {
            extensions.iter().find_map(|ext| match ext {
                Extension::SendersEntropy(ent) => Some(ent),
                _ => None,
            })
        } else {
            None
        }
    }

    pub fn get_multicast_group(&self) -> Option<u8> {
        if let Some(extensions) = &self.extensions {
            extensions.iter().find_map(|ext| match ext {
                Extension::MulticastGroupId(id) => Some(*id),
                _ => None,
            })
        } else {
            None
        }
    }

    pub fn get_mpan_state(&self) -> Option<(u8, &[u8; 16])> {
        if let Some(extensions) = &self.extensions {
            extensions.iter().find_map(|ext| match ext {
                Extension::MpanState(group, mpan_state) => Some((*group, mpan_state)),
                _ => None,
            })
        } else {
            None
        }
    }

    pub fn is_multicast_out_of_sync(&self) -> bool {
        if let Some(extensions) = &self.extensions {
            extensions
                .iter()
                .any(|ext| matches!(ext, Extension::MulticastOutOfSync))
        } else {
            false
        }
    }

    pub fn extract_excrypted_extensions<'a>(&mut self, plaintext_payload: &'a [u8]) -> &'a [u8] {
        if let Some((mut decrypted_extensions, remaining_data)) =
            parse_decrypted_extensions(plaintext_payload)
        {
            self.extensions
                .get_or_insert_with(Vec::new)
                .append(&mut decrypted_extensions);
            remaining_data
        } else {
            plaintext_payload
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    SendersEntropy(PartialEntropyInput),
    MpanState(u8, [u8; 16]),
    MulticastGroupId(u8),
    MulticastOutOfSync,
}

pub fn parse_decrypted_extensions(input: &[u8]) -> Option<(Vec<Extension>, &[u8])> {
    let mut extensions: Vec<Extension> = vec![];
    let mut data = input;
    loop {
        let (length, remaining_data) = data.split_first()?;
        if (*length < 2) || (data.len() < (*length as usize)) {
            break;
        }
        let length = *length as usize;
        data = remaining_data;

        let (second_byte, remaining_data) = data.split_first()?;
        data = remaining_data;
        let ext_type = *second_byte & 0b0001_1111;
        let more_to_follow = (*second_byte & 0b1000_0000) != 0;
        let (value, remaining_data) = data.split_at(length - 2);
        data = remaining_data;

        match ext_type {
            1 if let Ok(bytes) = value.try_into() => {
                extensions.push(Extension::SendersEntropy(PartialEntropyInput::new(bytes)));
            }
            2 if value.len() == 17 => {
                let group = value[0];
                if let Ok(bytes) = value[1..17].try_into() {
                    extensions.push(Extension::MpanState(group, bytes));
                }
            }
            3 if !value.is_empty() => {
                extensions.push(Extension::MulticastGroupId(value[0]));
            }
            4 if value.is_empty() => {
                extensions.push(Extension::MulticastOutOfSync);
            }
            _ => {}
        }
        if !more_to_follow {
            break;
        }
    }
    Some((extensions, data))
}

impl EncryptedEncapsulation {
    pub fn deserialize<'a>(
        data: &'a [u8],
        sender: NodeId,
        receiver: &crate::types::Destination,
        home: crate::types::HomeId,
    ) -> Option<(Self, &'a [u8])> {
        let nsdu_length = data.len() as u16;
        let (header, data) = data.split_at_checked(2)?;

        if header != [0x9F, 0x03] {
            return None;
        }

        let command_payload = data;

        let (sequence_number, data) = data.split_first()?;
        let sequence_number = *sequence_number;

        let (has_extension, mut data) = data.split_first()?;
        let (has_extension, has_encrypted_extensions) = (
            ((*has_extension & 0b0000_0001) != 0),
            ((*has_extension & 0b0000_0010) != 0),
        );

        if has_encrypted_extensions {
            print!("\n\n\nHAS ENCRYPTED EXTENSIONS!\n\n\n")
        }

        let mut extensions: Option<Vec<Extension>> = None;
        if has_extension {
            let (unencrypted_extensions, remaining_data) = parse_decrypted_extensions(data)?;
            extensions = Some(unencrypted_extensions);
            data = remaining_data;
        }

        let aad_destination = if let crate::types::Destination::Single(node) = receiver {
            Destination::Singlecast(*node)
        } else if let Some(unencrypted_extensions) = extensions.as_ref()
            && let Some(Extension::MulticastGroupId(group)) = unencrypted_extensions
                .iter()
                .find(|ext| matches!(ext, Extension::MulticastGroupId(_)))
        {
            Destination::Multicast(*group)
        } else {
            return None;
        };

        Some((
            Self {
                sequence_number,
                extensions,
                has_encrypted_extensions,
                aad: AdditionalAuthenticatedData {
                    sender,
                    destination: aad_destination,
                    home,
                    nsdu_length,
                    unencrypted: command_payload[..command_payload.len() - data.len()].to_vec(),
                },
            },
            data,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceReport {
    pub sequence_number: u8,
    pub mpan_out_of_sync: bool,
    pub span_out_of_sync: bool,
    pub entropy: PartialEntropyInput,
}

impl NonceReport {
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        let (header, data) = data.split_at_checked(2)?;

        if header != [0x9F, 0x02] {
            return None;
        }

        let (sequence_number, data) = data.split_first()?;
        let sequence_number = *sequence_number;

        // SOS please someone help me. It's not healthy
        let (sync_flags, data) = data.split_first()?;
        let span_out_of_sync = (*sync_flags & 0b0000_0001) != 0;
        let mpan_out_of_sync = (*sync_flags & 0b0000_0010) != 0;
        let entropy = PartialEntropyInput::new(data.get(..16)?.try_into().ok()?);
        Some(Self {
            sequence_number,
            mpan_out_of_sync,
            span_out_of_sync,
            entropy,
        })
    }
}

// ==========================================
// Tests
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ckdf_network_key_expansion() {
        let network_key = Key(hex_literal::hex!("e0ff431eb430fa03c85f519adc3aa518"));
        let key_expansion = NetworkKeyExpansion::new(&network_key);

        let expected_ccm_key = hex_literal::hex!("9a66d96011e32ab039b1fec51d2890a0");
        let expected_personalization_string =
            hex_literal::hex!("0a1ca977daafc6e4d1c3880cc8de0300dd1af08675c6fcf6a58c2e6aa110496f");

        assert_eq!(
            key_expansion.ccm_key.0, expected_ccm_key,
            "CCM Key did not match!"
        );
        assert_eq!(
            key_expansion.personalization_string.0, expected_personalization_string,
            "Personalization String did not match!"
        );
    }

    #[test]
    fn test_mixed_entropy() {
        let public_entropy =
            PartialEntropyInput::new(hex_literal::hex!("2fb9b45a6d0a12b789cbc1ce4f2e0b51"));
        let sender_entropy =
            PartialEntropyInput::new(hex_literal::hex!("634f03d2407df9d6b21195ce6887eb71"));
        let mixed_entropy = public_entropy.with_senders_entropy(&sender_entropy);

        let expected_mixed_entropy =
            hex_literal::hex!("a74c35a9e38b89a9c7e2624f8ea6b59a2131a95f677958fe57fd0edd2022a1b0");

        assert_eq!(
            mixed_entropy.0, expected_mixed_entropy,
            "MixedEntropy did not match!"
        );
    }

    #[test]
    fn test_drbg_instantiation() {
        let mei_bytes =
            hex_literal::hex!("a74c35a9e38b89a9c7e2624f8ea6b59a2131a95f677958fe57fd0edd2022a1b0");
        let pers_bytes =
            hex_literal::hex!("0a1ca977daafc6e4d1c3880cc8de0300dd1af08675c6fcf6a58c2e6aa110496f");

        let entropy = DerivedEntropy(mei_bytes);
        let pers_string = PersonalizationString(pers_bytes);

        let drbg = CtrDrbg::new(&entropy, &pers_string);

        let expected_key = hex_literal::hex!("f5b26010c35a7f2c205ef714e29ff3c0");
        let expected_v = hex_literal::hex!("ffa383177209079a0159e20ef08016a7");

        assert_eq!(drbg.key.0, expected_key, "DRBG Key did not match!");
        assert_eq!(drbg.value.0, expected_v, "DRBG V did not match!");
    }

    #[test]
    fn test_drbg_generation() {
        let mei_bytes =
            hex_literal::hex!("a74c35a9e38b89a9c7e2624f8ea6b59a2131a95f677958fe57fd0edd2022a1b0");
        let pers_bytes =
            hex_literal::hex!("0a1ca977daafc6e4d1c3880cc8de0300dd1af08675c6fcf6a58c2e6aa110496f");

        let mut drbg = CtrDrbg::new(
            &DerivedEntropy(mei_bytes),
            &PersonalizationString(pers_bytes),
        );

        let nonce: [u8; 13] = drbg.generate();

        let expected_nonce = hex_literal::hex!("e30aeb88ec029b5041d5411363");
        assert_eq!(nonce, expected_nonce, "Generated nonce did not match!");
    }

    #[test]
    fn test_nist_cavp_vectors() {
        struct TestCase {
            entropy: &'static str,
            personal: &'static str,
            rand: &'static str,
        }

        let vectors = [
            TestCase {
                entropy: "cee23de86a69c7ef57f6e1e12bd16e35e51624226fa19597bf93ec476a44b0f2",
                personal: "a2ef16f226ea324f23abd59d5e3c660561c25e73638fe21c87566e86a9e04c3e",
                rand: "2a76d71b329f449c98dc08fff1d205a2fbd9e4ade120c7611c225c984eac8531288dd3049f3dc3bb3671501ab8fbf9ad49c86cce307653bd8caf29cb0cf07764",
            },
            TestCase {
                entropy: "b09eb4a82a39066ec945bb7c6aef6a0682a62c3e674bd900297d4271a5f25b49",
                personal: "a3b768adcfe76d61c972d900da8dffeeb2a42e740247aa719ed1c924d2d10bd4",
                rand: "5a1c26803f3ffd4daf32042fdcc32c3812bb5ef13bc208cef82ea047d2890a6f5dcecf32bcc32a2585775ac5e1ffaa8de00664c54fe00a7674b985619e953c3a",
            },
            TestCase {
                entropy: "0bbc898f8daf3f12fc009c846fe2cea22f683a432eea297257312d5a44bac131",
                personal: "8d34be9d8110b84b02a60508deae773c1a808f4e2a0ec81747ae2ec923fe99a9",
                rand: "da49e24a6cb1d9e51b98ea6103627d9ad035770b7bdc760606e2b5f35afd13b7a61a4a18fac25258985fa1fb2b88a7cc17278b0539d7cf74f940f008ee2cf4cd",
            },
            TestCase {
                entropy: "3ea1f3fb153636c33982464f0e5b0daeba59c3f1ee91a612c4f6a9dcfcd0a978",
                personal: "ea8671fc9c02584d69af91de2adacec1408d91d512718945ed1e7dc0b620b323",
                rand: "2429e7d817cfd4f8500948d2ec2dec02b7d035b4bb986144bb918a31bfd2269e6907c34ac8beab69508869a4f04bc3c23ccfbae5d59eab857ece000d554b273a",
            },
            TestCase {
                entropy: "b6b2033e382decd21e4eabd8f1177761d06a12bae1cfed0059b7e16bd9bab8d7",
                personal: "c99a49132543fce49b804e9f417d22e49c460bc4e60a6d36701fea561b93203d",
                rand: "63626608b446c7d02212209d0a3888e40534864d8f5cd28aaff09505ee5e894751e5cb8467a5d85d87a675b7852724deb0d12038035400c3405fafb1a47f88c8",
            },
            TestCase {
                entropy: "acc465d1bf94ccdeec06c74c812db3a993c408b5c2ef7ebe9bdeb6a1a51976a7",
                personal: "77278d47a169c559518d46ffb23aa594efdaebb067c48d4a392f60b94cc15b36",
                rand: "e0e6e417de8fc5d212bdda4c026a13d6eae402874d62c30577ee4c3445ace85479cbc3b55bbbe1573c13f9b0242d7e3f6e7e91d932b3d5a6dca8df43c188ae5e",
            },
            TestCase {
                entropy: "14b33415d2321fbb10a768ced712c8999ff2f19b63264a81adc2fdc16370b185",
                personal: "029b48805285349c292a99ee68fcefda1f61dd60a09f4616cb2efe4f8b140056",
                rand: "8a69feb26be025a3849bb0b60959717daa59c889c383593d1f8debf58051eb463d07c659cfbe47e94224ba18833b71d95905e0cde785364a87706e31297fb323",
            },
            TestCase {
                entropy: "5a83af23cafb30e3a18e28651b3c1bd01813c44216e7e44b790d6664e2c3839a",
                personal: "d0f108ae7c65e16cfa13e5582204eb8cd6ebb08f1f6a5d476c275247c1a83eb5",
                rand: "e64397f0eea0d33d9715bcef2ee7eec22a86e8d066a25e44706dc688c499bd7ef08172c8cf36e3bddf79f2bec136a01aad844930e48a16fe1800d69fb0f4e163",
            },
            TestCase {
                entropy: "1dc24dd9d6a405a007bd082cfbdbd863185e072b67d663b14d7e8f16900cfce6",
                personal: "0eca85ddcb6f38ff3683968ef98b52408428dcae2ec3b0fa4c68906c1b6481cd",
                rand: "156938566fc25d493c1c60d8925819a6e59a2479d75f3efff16d46aada68403140407955c1fd9d2a890bcf67ac9b3b82d1d6cf788fd863da3d41ac6e34f217a0",
            },
            TestCase {
                entropy: "ecb7e61a4792a2115213d141d20710e8a3212d7847dd53dfa5d4d7777d10d97e",
                personal: "bf09235d30cd69ada285948fe1be2e0c4e145ac8485d12ca7b8239136da1c638",
                rand: "868db5832b2e9c3d2c9794b174b328ed2cc86e41017863eabc4a7c096a487bfe4d67ccf93a5e2c67d88dbd8f1419b2a9f1293e7a70e8e8fe93e2156496b0fa54",
            },
            TestCase {
                entropy: "e55727c590ec3ac108f4e5fec39a2d34bf89aee4e215dcc970db8ae8f6a0e4a8",
                personal: "ade3d28a8e43aab8fd31dec8bdbe5c41c0b3f7f69a2d0aada5608ab0e57c8bb0",
                rand: "198742299feecf6083e3a0bef75ac2b93de2defa6525883a55f88247dc6902279f792402faffe4a81213e40facb873cd499e4b0f7f0ff592bc06699db773b899",
            },
            TestCase {
                entropy: "c380dafd84f2782b7539ca1c3ad9715fe6b1805310a578afcffc9210ac127ded",
                personal: "b298533d9c74a0d9b9aa0d82edc434002b4d1372318c2865b7700a5b7ebeabf0",
                rand: "9aec7a5ba3e091e6a6c99e04395af2ab2eeaa1ef089baa51dc23ea31603b899ea298317603354f38fd9c36c2a53a05c1e468c6ae32fe4c3b0056ec0d5eff22b6",
            },
            TestCase {
                entropy: "f158210535a404f6cb4f9550b3f26e3f777a9faa164774749f48ef4a8ce09449",
                personal: "d56fa873cc762f64b3ab31b6291e247efca71fca90453cfff1f2b0b3e265c475",
                rand: "034b41b2a9a6764e5ed1edb00aea3185fe43eb81b4253e7cade97956fccd9fc5782328fada8ed5208f1d46b1f872e333b9e2f036a51746ccaf39e1a85af8eb23",
            },
            TestCase {
                entropy: "973a99b7e03b393ef689af8cb90d7436cae10e4814814aed342dd38e2a7346e3",
                personal: "300d3d2adbac6d7ddadde07e08b0d72b5b39ff36031e81d8303958242e3cf03f",
                rand: "62012842991fe3220f1d961045f028a3b6a729f5a451b8c2ec90e1c1e2b1e4042e97267e1bfa1782a10c3c29509bc8f2adffd3d695861e1594da91702830faf7",
            },
            TestCase {
                entropy: "22d1d8c8bde76a239d032804717face16d77b51170d0f53ccbcca4eaff4fb315",
                personal: "5d3a7d40fdf95b98454bca03c6fcbf6abf3807de75171b55bab2db5a3f5f12f2",
                rand: "1007e11f48e3c4813fddd67310db56d67a49fe93e45e61b37ba81485df6a62ee57ca41fa1d987f467c2939790a20421c2b4f70b28fb0b90bbeab1ac0ae884f1a",
            },
        ];

        for (i, vector) in vectors.iter().enumerate() {
            let mut entropy_bytes = [0u8; 32];
            hex::decode_to_slice(vector.entropy, &mut entropy_bytes).unwrap();

            let mut personal_bytes = [0u8; 32];
            hex::decode_to_slice(vector.personal, &mut personal_bytes).unwrap();

            let mut expected_rand_bytes = [0u8; 64];
            hex::decode_to_slice(vector.rand, &mut expected_rand_bytes).unwrap();

            let entropy = DerivedEntropy(entropy_bytes);
            let personal = PersonalizationString(personal_bytes);

            let mut drbg = CtrDrbg::new(&entropy, &personal);

            let _first_call: [u8; 64] = drbg.generate();
            let second_call: [u8; 64] = drbg.generate();

            assert_eq!(
                second_call, expected_rand_bytes,
                "NIST CAVP Vector {} failed!",
                i
            );
        }
    }

    #[test]
    fn test_full_s2_multicast_decryption() {
        let permanent_network_key = Key(hex_literal::hex!("acacacacacacacacacacacacacacacac"));
        let nk_expansion = NetworkKeyExpansion::new(&permanent_network_key);
        let mpan_inner_state: [u8; 16] = hex_literal::hex!("deadbeefdeadbeefdeadbeefdeadbeef");

        let aad = AdditionalAuthenticatedData {
            sender: NodeId(1),
            destination: Destination::Multicast(2),
            home: HomeId(0xdeadbeef),
            nsdu_length: 0x0018,
            unencrypted: hex_literal::hex!("9c01034302").to_vec(),
        };

        let ciphertext = hex_literal::hex!("eb8b36297656ac6e97d6c1eb1fec24d0654eebbb4648fed4");
        let expected_plaintext = hex_literal::hex!("48656c6c6f206d756c74696361737421");

        let mut mpan = MpanState {
            inner_state: mpan_inner_state,
            security_class: SecurityClass::Unauthenticated,
        };
        let plaintext = mpan
            .decrypt_s2_frame(&nk_expansion, aad, &ciphertext)
            .expect("AES-CCM Decryption Failed (Authentication Tag Mismatch)");

        assert_eq!(
            plaintext, expected_plaintext,
            "Decrypted plaintext did not match expected!"
        );
    }

    #[test]
    fn test_aad_into_be_bytes() {
        let aad_classic = AdditionalAuthenticatedData {
            sender: NodeId(2),
            destination: Destination::Singlecast(NodeId(1)),
            home: HomeId(0x12345678),
            nsdu_length: 0x002B,
            unencrypted: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes_classic = aad_classic.into_be_bytes();
        assert_eq!(
            bytes_classic,
            vec![
                0x02, 0x01, 0x12, 0x34, 0x56, 0x78, 0x00, 0x2B, 0xAA, 0xBB, 0xCC
            ]
        );

        let aad_lr_sender = AdditionalAuthenticatedData {
            sender: NodeId(257),
            destination: Destination::Singlecast(NodeId(1)),
            home: HomeId(0x12345678),
            nsdu_length: 0x002B,
            unencrypted: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes_lr_sender = aad_lr_sender.into_be_bytes();
        assert_eq!(
            bytes_lr_sender,
            vec![
                0x01, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x00, 0x2B, 0xAA, 0xBB, 0xCC
            ]
        );

        let aad_lr_dest = AdditionalAuthenticatedData {
            sender: NodeId(2),
            destination: Destination::Singlecast(NodeId(258)),
            home: HomeId(0x12345678),
            nsdu_length: 0x002B,
            unencrypted: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes_lr_dest = aad_lr_dest.into_be_bytes();
        assert_eq!(
            bytes_lr_dest,
            vec![
                0x00, 0x02, 0x01, 0x02, 0x12, 0x34, 0x56, 0x78, 0x00, 0x2B, 0xAA, 0xBB, 0xCC
            ]
        );

        let aad_multicast = AdditionalAuthenticatedData {
            sender: NodeId(2),
            destination: Destination::Multicast(3),
            home: HomeId(0x12345678),
            nsdu_length: 0x002B,
            unencrypted: vec![0xAA, 0xBB, 0xCC],
        };
        let bytes_multicast = aad_multicast.into_be_bytes();
        assert_eq!(
            bytes_multicast,
            vec![
                0x02, 0x03, 0x12, 0x34, 0x56, 0x78, 0x00, 0x2B, 0xAA, 0xBB, 0xCC
            ]
        );
    }

    #[test]
    fn test_my_decryption() {
        let pnk_mesh_auth = Key(hex_literal::hex!("99a46f6a6e2e0417679d894faee3c50d"));
        let pnk_mesh_ac = Key(hex_literal::hex!("e0ff431eb430fa03c85f519adc3aa518"));
        let pnk_unauth = Key(hex_literal::hex!("a2e2828a4d254e1d92f221a6cf7e6b3b"));

        let base_state_val =
            u128::from_be_bytes(hex_literal::hex!("9f3f3144efc4ae4dc87730f863bed098"));

        let aad = AdditionalAuthenticatedData {
            sender: NodeId(1),
            destination: Destination::Multicast(1),
            home: HomeId(0xfdd09bc7),
            nsdu_length: 0x0013,
            unencrypted: hex_literal::hex!("dd01034301").to_vec(),
        };

        let ciphertext = hex_literal::hex!("4db76f7339080704606ebfd7");

        for (name, pnk) in [
            ("MeshAuth", pnk_mesh_auth),
            ("MeshAc", pnk_mesh_ac),
            ("Unauth", pnk_unauth),
        ] {
            let nk_expansion = NetworkKeyExpansion::new(&pnk);
            for offset in -10..=10 {
                let mpan_inner_state = (base_state_val.wrapping_add(offset as u128)).to_be_bytes();
                let mut mpan = MpanState {
                    inner_state: mpan_inner_state,
                    security_class: SecurityClass::Unauthenticated,
                };
                if let Ok(plaintext) =
                    mpan.decrypt_s2_frame(&nk_expansion, aad.clone(), &ciphertext)
                {
                    println!(
                        "SUCCESS for 0xDD! Key: {}, Offset: {}, Plaintext: {}",
                        name,
                        offset,
                        hex::encode(plaintext)
                    );
                }
            }
        }

        // Test 0xDF frame as well
        let aad_df = AdditionalAuthenticatedData {
            sender: NodeId(1),
            destination: Destination::Multicast(1),
            home: HomeId(0xfdd09bc7),
            nsdu_length: 0x0013,
            unencrypted: hex_literal::hex!("df01034301").to_vec(),
        };
        let ciphertext_df = hex_literal::hex!("e9412418e0b9f3eaab1258f6");

        for (name, pnk) in [
            ("MeshAuth", pnk_mesh_auth),
            ("MeshAc", pnk_mesh_ac),
            ("Unauth", pnk_unauth),
        ] {
            let nk_expansion = NetworkKeyExpansion::new(&pnk);
            for offset in -10..=10 {
                let mpan_inner_state = (base_state_val.wrapping_add(offset as u128)).to_be_bytes();
                let mut mpan = MpanState {
                    inner_state: mpan_inner_state,
                    security_class: SecurityClass::Unauthenticated,
                };
                if let Ok(plaintext) =
                    mpan.decrypt_s2_frame(&nk_expansion, aad_df.clone(), &ciphertext_df)
                {
                    println!(
                        "SUCCESS for 0xDF! Key: {}, Offset: {}, Plaintext: {}",
                        name,
                        offset,
                        hex::encode(plaintext)
                    );
                }
            }
        }
    }
}
