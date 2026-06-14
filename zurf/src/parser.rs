// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::frame::{Frame, FrameType};
use crate::keys::{KeyStore, LruKeyStore};
use crate::mpdu::EncapsulationCommand;
use crate::types::{ParseError, ParseResult};

pub struct Parser {
    pub(crate) keystore: LruKeyStore,
}

impl Parser {
    pub fn new(keystore: LruKeyStore) -> Self {
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

            if nsdu.payload.is_none() || frame.channel.is_none() {
                data = rest;
                frames.push(frame);
                continue;
            }

            let mut nested_payload: Option<EncapsulationCommand> = None;
            match nsdu.payload.as_ref().unwrap() {
                EncapsulationCommand::S2Nonce(nonce_report) => {
                    self.keystore.cache_s2_nonce(
                        nsdu.home_id,
                        nsdu.source_node_id,
                        nonce_report.clone(),
                    );
                }
                EncapsulationCommand::Security2Encrypted(encrypted_encapsulation, items) => {
                    nested_payload = Some(self.keystore.decrypt_s2(
                        frame.channel.unwrap().is_long_range(),
                        nsdu.home_id,
                        nsdu.source_node_id,
                        &nsdu.destination,
                        encrypted_encapsulation.clone(),
                        items,
                    ));
                }
                _ => {}
            }
            if nested_payload.is_some() {
                nsdu.payload = nested_payload
            }
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
        let mut parser = Parser::new(LruKeyStore::default());
        let incomplete_data = [0x21, 0x05, 0x00];
        assert_eq!(
            parser.parse_next(&incomplete_data),
            Ok((vec![], &incomplete_data[..]))
        );
    }
}
