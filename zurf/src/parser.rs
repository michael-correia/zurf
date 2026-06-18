// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::frame::{Frame, FrameType};
use crate::keys::{KeyStore, LruKeyStore};
use crate::mpdu::{EncapsulationCommand, TransportServiceEncapsulation};
use crate::types::{Destination, HomeId, NodeId, ParseError, ParseResult};

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
    next_transport_service_index: usize,
}

impl Parser {
    pub fn new(keystore: LruKeyStore) -> Self {
        Self {
            keystore,
            transport_service_cache: Default::default(),
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
                self.keystore
                    .cache_s2_nonce(home, sender, nonce_report.clone());
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
}
