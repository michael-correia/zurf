// SPDX-License-Identifier: LGPL-3.0-or-later

use zurf_enum_derive::TryFromU8;

use crate::{
    security::s2::{EncryptedEncapsulation, NonceReport},
    types::{
        Channel, DataSpeed, Destination, HomeId, Hop, NodeId, ParseError, ParseResult, Rssi,
        RssiError, lr_rssi_from_byte, noise_floor_from_byte, tx_power_from_byte,
    },
};

// ==========================================
// Enums
// ==========================================

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpduHeaderType {
    Singlecast = 1,
    Multicast = 2,
    Ack = 3,
    Flooded = 4,
    Explore = 5,
    AudioVideo = 6,
    AudioVideoAck = 7,
    Routed = 8,
    Raw = 9,
    //A broadcast frame is a singlecast frame (header type 0x1) carrying destination NodeID = 0xFF; see clause A.4.2.6.
    Broadcast = 10,
}

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingResult {
    Ack = 0b010,
    Err = 0b100,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeamingType {
    Long,
    Short,
    Fragmented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorerDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorerPayload {
    Normal,
    InclusionInformation {
        home: Option<HomeId>,
    },
    Search {
        source_node: NodeId,
        frame_handle: u8,
        result_repeaters: Vec<NodeId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CRCMode {
    CrcCcitt(u16),
    XorChecksum(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportServiceEncapsulation {
    pub sender: NodeId,
    pub destination: Destination,
    pub home: HomeId,
    pub session: u8,
    pub datagram_size: usize,
    pub datagram_offset: usize,
    pub buffer: Vec<u8>,
}

impl TransportServiceEncapsulation {
    pub fn deserialize(
        data: &[u8],
        sender: NodeId,
        destination: &Destination,
        home: HomeId,
    ) -> Result<Self, ParseError> {
        let (header, data) = data.split_at_checked(2).ok_or(ParseError::Incomplete)?;
        let size_10_to_8 = header[1] & 0b0000_0111;
        let cmd_byte = (header[1] & !0b0000_0111) >> 3;
        let is_first_segment = match [header[0], cmd_byte] {
            [0x55, 0x18] => true,
            [0x55, 0x1C] => false,
            _ => {
                return Err(ParseError::Invalid);
            }
        };

        let (size_7_to_0, data) = data.split_first().ok_or(ParseError::Incomplete)?;
        // I think this is only useful for first segment? But it's included every time
        let datagram_size = (size_10_to_8 as usize) << 8 | *size_7_to_0 as usize;
        let (metadata, mut data) = data.split_first().ok_or(ParseError::Incomplete)?;
        let session = (*metadata & 0b1111_0000) >> 4;
        let extensions = (*metadata & 0b0000_1000) != 0;
        let datagram_offset = if is_first_segment {
            0_usize
        } else {
            let offset_10_to_8 = (*metadata & 0b0000_0111) as usize;
            let (offset_7_to_0, remaining) = data.split_first().ok_or(ParseError::Incomplete)?;
            data = remaining;
            (offset_10_to_8 << 8) | (*offset_7_to_0 as usize)
        };
        if extensions {
            // let's just skip over them
            let (extension_length, remaining) = data.split_first().ok_or(ParseError::Incomplete)?;
            data = remaining;
            let (_, remaining) = data
                .split_at_checked(*extension_length as usize)
                .ok_or(ParseError::Incomplete)?;
            data = remaining;
        }

        // The rest is data up to the 2-byte FCS
        let payload_len = data.len().checked_sub(2).ok_or(ParseError::Incomplete)?;
        if datagram_size < payload_len {
            return Err(ParseError::Invalid);
        }
        let buffer = data[..payload_len].to_vec();

        Ok(Self {
            sender,
            destination: destination.clone(),
            home,
            session,
            datagram_size,
            datagram_offset,
            buffer,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncapsulationCommand {
    SupervisionGet(Box<EncapsulationCommand>),
    Security2Encrypted(EncryptedEncapsulation, Vec<u8>),
    Security2Decrypted(EncryptedEncapsulation, Box<EncapsulationCommand>),
    Security0Encrypted(crate::security::s0::EncryptedEncapsulation, Vec<u8>),
    Security0DecryptedFirst(crate::security::s0::EncryptedEncapsulation, Vec<u8>),
    Security0DecryptedSecond(crate::security::s0::EncryptedEncapsulation, Vec<u8>),
    Security0Decrypted(
        crate::security::s0::EncryptedEncapsulation,
        Box<EncapsulationCommand>,
    ),
    Security0(Box<EncapsulationCommand>),
    CRC16(Box<EncapsulationCommand>),
    MultiCommand(Vec<EncapsulationCommand>),
    //MultiChannel ?,
    S2Nonce(NonceReport),
    TransportFirstSegment(TransportServiceEncapsulation),
    TransportSegment(TransportServiceEncapsulation),
    Unencapsulated(Vec<u8>),
}

impl EncapsulationCommand {
    pub fn parse(
        data: Vec<u8>,
        sender: NodeId,
        receiver: &crate::types::Destination,
        home: crate::types::HomeId,
    ) -> Self {
        match data.get(..2) {
            Some(&[0x98, 0x81]) | Some(&[0x98, 0xC1]) => {
                let frame = crate::security::s0::EncryptedEncapsulation::deserialize(&data);
                if let Some((encapsulation, payload)) = frame {
                    EncapsulationCommand::Security0Encrypted(encapsulation, payload)
                } else {
                    EncapsulationCommand::Unencapsulated(data)
                }
            }
            Some(&[0x9F, 0x02]) => NonceReport::deserialize(data.as_slice())
                .map(EncapsulationCommand::S2Nonce)
                .unwrap_or_else(|| EncapsulationCommand::Unencapsulated(data)),
            Some(&[0x9F, 0x03]) => {
                EncryptedEncapsulation::deserialize(data.as_slice(), sender, receiver, home)
                    .map(|(encap, ciphertext)| {
                        EncapsulationCommand::Security2Encrypted(encap, ciphertext.to_vec())
                    })
                    .unwrap_or_else(|| EncapsulationCommand::Unencapsulated(data))
            }
            Some(&[0x55, cmd_byte]) => {
                let cmd = cmd_byte >> 3;
                if cmd == 0x18 || cmd == 0x1C {
                    TransportServiceEncapsulation::deserialize(
                        data.as_slice(),
                        sender,
                        receiver,
                        home,
                    )
                    .map(|cache| {
                        if cmd == 0x18 {
                            EncapsulationCommand::TransportFirstSegment(cache)
                        } else {
                            EncapsulationCommand::TransportSegment(cache)
                        }
                    })
                    .unwrap_or_else(|_| EncapsulationCommand::Unencapsulated(data))
                } else {
                    EncapsulationCommand::Unencapsulated(data)
                }
            }
            _ => EncapsulationCommand::Unencapsulated(data),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingExtension {
    Routed(RoutedNetworkProtocolDataUnit),
    Explore(ExploreNetworkProtocolDataUnit),
}

// ==========================================
// Structs & Implementations
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedNetworkProtocolDataUnit {
    pub routed_result: Option<RoutingResult>,
    pub failed_hop: Option<Hop>,
    pub repeaters: Option<Vec<Hop>>,
    pub beaming: Option<BeamingType>,
}

impl RoutedNetworkProtocolDataUnit {
    pub fn deserialize<'a>(data: &'a [u8], channel: &Channel) -> ParseResult<'a, Self> {
        let mut index = 0;
        let first_byte = data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;
        let routed_result = RoutingResult::try_from(first_byte & 0b0000_0110).ok();
        let second_byte = data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;
        let num_repeaters = ((second_byte & 0xF0) >> 4) as usize;
        if num_repeaters > 4 {
            return Err(ParseError::Invalid);
        }
        let mut repeaters: Option<Vec<Hop>> = if num_repeaters == 0 {
            None
        } else {
            Some(
                data.get(index..index + num_repeaters)
                    .ok_or(ParseError::Incomplete)?
                    .iter()
                    .map(|&node| Hop {
                        node: NodeId(node as u16),
                        rssi: Err(RssiError::NotAvailable),
                    })
                    .collect(),
            )
        };
        index += num_repeaters;

        let mut beaming = match channel {
            Channel::Mesh3 => {
                let dest_wakeup_data = data.get(index).ok_or(ParseError::Incomplete)?;
                index += 1;
                match dest_wakeup_data {
                    0x02 => Some(BeamingType::Fragmented),
                    _ => None,
                }
            }
            _ => None,
        };
        let extended_headers_available = (first_byte & 0b0000_1000) != 0;
        if extended_headers_available {
            let header_info = data.get(index).ok_or(ParseError::Incomplete)?;
            index += 1;
            let (header_len, header_type) = ((header_info & 0xF0) >> 4, header_info & 0x0F);
            match (header_len, header_type) {
                (1, 0) => {
                    let beaming_extension = data.get(index).ok_or(ParseError::Incomplete)?;
                    index += 1;
                    beaming = match beaming_extension & 0b0110_0000 {
                        0b0100_0000 => Some(BeamingType::Long),
                        0b0010_0000 => Some(BeamingType::Short),
                        _ => beaming,
                    }
                }
                (4, 1) => {
                    let rssi_data = data.get(index..index + 4).ok_or(ParseError::Incomplete)?;
                    index += 4;
                    if let Some(ref mut repeater_list) = repeaters {
                        for hop in repeater_list.iter_mut().zip(rssi_data.iter()) {
                            hop.0.rssi = Hop::rssi_from_byte(*hop.1);
                        }
                    }
                }

                _ => return Err(ParseError::Invalid),
            }
        }
        let mut failed_hop: Option<Hop> = None;
        if routed_result == Some(RoutingResult::Err)
            && let Some(ref repeaters) = repeaters
        {
            let failed_hop_index = ((first_byte & 0xF0) >> 4) as usize;
            failed_hop = repeaters.get(failed_hop_index).copied();
        }

        Ok((
            Self {
                routed_result,
                failed_hop,
                repeaters,
                beaming,
            },
            &data[index..],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploreNetworkProtocolDataUnit {
    pub command: ExplorerPayload,
    pub direction: ExplorerDirection,
    pub random_tx_interval: u8,
    pub repeaters: Option<Vec<NodeId>>,
}

impl ExploreNetworkProtocolDataUnit {
    pub fn deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, Self> {
        let mut index = 0;
        let first_byte = data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;
        let (version, command) = ((first_byte & 0b1110_0000) >> 5, first_byte & 0b0001_1111);
        if version != 1 {
            // We don't know how to parse future undefined versions.
            return Err(ParseError::Invalid);
        }

        let direction = match (data.get(index).ok_or(ParseError::Incomplete)? & 0b0000_0010) >> 1 {
            0 => ExplorerDirection::Outbound,
            _ => ExplorerDirection::Inbound,
        };
        index += 1;

        let random_tx_interval = *data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;

        // ignore repeater count
        index += 1;

        let mut repeaters: Vec<NodeId> = Vec::with_capacity(4);
        for _ in 0..4 {
            let node = *data.get(index).ok_or(ParseError::Incomplete)?;
            index += 1;
            if node != 0 {
                repeaters.push(NodeId(node as u16));
            }
        }

        let command = match command {
            0 => ExplorerPayload::Normal,
            1 => {
                let home = data.get(index..index + 4).ok_or(ParseError::Incomplete)?;
                index += 4;

                let home = u32::from_be_bytes(home.try_into().unwrap());
                let home = if home == 0 { None } else { Some(HomeId(home)) };
                ExplorerPayload::InclusionInformation { home }
            }
            2 => {
                let source_node = NodeId(*data.get(index).ok_or(ParseError::Incomplete)? as u16);
                index += 1;
                let frame_handle = *data.get(index).ok_or(ParseError::Incomplete)?;
                index += 1;

                // ignore ttl / repeater count result
                index += 1;
                let result_repeaters: Vec<NodeId> = data
                    .get(index..index + 4)
                    .ok_or(ParseError::Incomplete)?
                    .iter()
                    .filter_map(|&node| {
                        if node == 0 {
                            None
                        } else {
                            Some(NodeId(node as u16))
                        }
                    })
                    .collect();

                index += 4;

                ExplorerPayload::Search {
                    source_node,
                    frame_handle,
                    result_repeaters,
                }
            }
            _ => return Err(ParseError::Invalid),
        };

        Ok((
            ExploreNetworkProtocolDataUnit {
                command,
                direction,
                random_tx_interval,
                repeaters: if repeaters.is_empty() {
                    None
                } else {
                    Some(repeaters)
                },
            },
            &data[index..],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
    pub home: HomeId,
    pub source_node: NodeId,
    pub header_type: MpduHeaderType,
    pub ack_requested: bool,
    pub low_power: bool, // Used for Neighbor discovery. Historically used in inclusion which mandated close proximity
    pub speed_modified: bool, // For point-to-point, look at frame control. For routed, look at routing extension
    pub sequence_number: u8,  // 4 bit in channels 1 and 2. 8 bit in channel 3
    pub routing_extension: Option<RoutingExtension>, // Channels 1 and 2. Channel 3 cannot be routed
    pub destination: Destination,
    pub beaming: Option<BeamingType>,
    pub payload: Option<EncapsulationCommand>,
    pub checksum: Option<CRCMode>,
    pub noise_floor: Option<Rssi>,
    pub tx_power: Option<Rssi>,
    pub incoming_rssi: Option<Rssi>,
}

impl std::default::Default for Data {
    fn default() -> Self {
        Self {
            home: HomeId::default(),
            source_node: NodeId::default(),
            header_type: MpduHeaderType::Singlecast,
            ack_requested: false,
            low_power: false,
            speed_modified: false,
            sequence_number: 0,
            routing_extension: None,
            destination: Destination::Single(NodeId::default()),
            beaming: None,
            payload: None,
            checksum: None,
            noise_floor: None,
            tx_power: None,
            incoming_rssi: None,
        }
    }
}

impl Data {
    fn crc_ccitt(data: &[u8]) -> u16 {
        data.iter()
            .flat_map(|&byte| {
                (0..8)
                    .rev()
                    .map(move |bit_index| ((byte >> bit_index) & 1) == 1)
            })
            .fold(0x1D0F, |mut crc, bit| {
                let c15 = (crc & 0x8000) != 0;
                crc <<= 1;
                if bit ^ c15 {
                    crc ^= 0x1021;
                }
                crc
            })
    }

    fn xor_checksum(data: &[u8]) -> u8 {
        data.iter().fold(0xFF, |mut checksum, &val| {
            checksum ^= val;
            checksum
        })
    }

    pub fn mesh_deserialize<'a>(
        data: &'a [u8],
        channel: &Channel,
        speed: &DataSpeed,
    ) -> ParseResult<'a, Self> {
        if data.is_empty() {
            return Err(ParseError::Empty);
        }
        let mut index: usize = 0;
        let mut mpdu = Self::default();

        let home_bytes = data.get(index..index + 4).ok_or(ParseError::Incomplete)?;
        mpdu.home = HomeId(u32::from_be_bytes(home_bytes.try_into().unwrap()));
        index += 4;

        let source_node = data.get(index).ok_or(ParseError::Incomplete)?;
        mpdu.source_node = NodeId(*source_node as u16);
        index += 1;

        let frame_control = data.get(index..index + 2).ok_or(ParseError::Incomplete)?;
        index += 2;

        match channel {
            Channel::Mesh1 | Channel::Mesh2 => {
                mpdu.ack_requested = frame_control[0] & 0x40 != 0;
                mpdu.low_power = frame_control[0] & 0x20 != 0;
                mpdu.speed_modified = frame_control[0] & 0x10 != 0;
                mpdu.header_type = if frame_control[0] & 0b1000_0000 != 0 {
                    MpduHeaderType::Routed
                } else {
                    MpduHeaderType::try_from(frame_control[0] & 0x0F)
                        .map_err(|_| ParseError::Invalid)?
                };
                mpdu.beaming = match frame_control[1] & 0x60 {
                    0x40 => Some(BeamingType::Long),
                    0x20 => Some(BeamingType::Short),
                    0x00 => None,
                    _ => {
                        return Err(ParseError::Invalid);
                    }
                };
                mpdu.sequence_number = frame_control[1] & 0x0F;
            }
            Channel::Mesh3 => {
                mpdu.ack_requested = frame_control[0] & 0x80 != 0;
                mpdu.low_power = frame_control[0] & 0x40 != 0;
                mpdu.header_type = MpduHeaderType::try_from(frame_control[0] & 0x0F)
                    .map_err(|_| ParseError::Invalid)?;
                mpdu.beaming = match frame_control[1] & 0x70 {
                    0x40 => Some(BeamingType::Fragmented),
                    0x20 => Some(BeamingType::Long),
                    0x10 => Some(BeamingType::Short),
                    0x00 => None,
                    _ => {
                        return Err(ParseError::Invalid);
                    }
                };
            }
            _ => {
                return Err(ParseError::Invalid);
            }
        }

        let mpdu_length = data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;

        let (min_len, max_len) = match (channel, mpdu.header_type) {
            (Channel::Mesh1 | Channel::Mesh2, MpduHeaderType::Multicast) => (41, 68),
            (Channel::Mesh1 | Channel::Mesh2, MpduHeaderType::Ack) => (10, 11),
            (Channel::Mesh1 | Channel::Mesh2, _) => (11, 65),
            (Channel::Mesh3, MpduHeaderType::Multicast) => (42, 170),
            (Channel::Mesh3, MpduHeaderType::Ack) => (12, 13),
            (Channel::Mesh3, _) => (13, 170),
            _ => return Err(ParseError::Invalid),
        };

        let mpdu_len_size = *mpdu_length as usize;
        if mpdu_len_size < min_len || mpdu_len_size > max_len || data.len() < mpdu_len_size {
            return Err(ParseError::Invalid);
        }

        if *channel == Channel::Mesh3 {
            let sequence_number = data.get(index).ok_or(ParseError::Incomplete)?;
            mpdu.sequence_number = *sequence_number;
            index += 1;
        }

        let dest_byte = data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;

        match mpdu.header_type {
            MpduHeaderType::Multicast => {
                let mask_header = dest_byte;
                let (address_offset, num_nodes) =
                    (*mask_header & 0b11100000, *mask_header & 0b00011111);
                let nodes = data
                    .get(index..index + num_nodes as usize)
                    .ok_or(ParseError::Incomplete)?;
                index += num_nodes as usize;
                // Since we'll count bits by total index in the mask,
                // and everyone who isn't a Matlab or R programmer knows indices start at 0...
                let address_offset = (address_offset + 1) as u16;
                mpdu.destination = Destination::Multicast(
                    nodes
                        .iter()
                        .flat_map(|&mask_byte| {
                            (0..8).map(move |byte_bit_num| (mask_byte & (1 << byte_bit_num)) != 0)
                        })
                        .enumerate()
                        .filter_map(|(bit_number, is_set)| {
                            if is_set {
                                return Some(NodeId(address_offset + bit_number as u16));
                            }
                            None
                        })
                        .collect(),
                );
            }

            MpduHeaderType::Singlecast
            | MpduHeaderType::Explore
            | MpduHeaderType::Routed
            | MpduHeaderType::Ack => {
                let dest_node = NodeId(*dest_byte as u16);
                if mpdu.header_type == MpduHeaderType::Singlecast && dest_node.is_broadcast() {
                    mpdu.header_type = MpduHeaderType::Broadcast;
                    mpdu.destination = Destination::Broadcast;
                } else {
                    mpdu.destination = Destination::Single(dest_node);
                }
            }
            _ => {}
        }

        mpdu.routing_extension = match mpdu.header_type {
            MpduHeaderType::Routed => {
                let (routing_extension, remaining_data) =
                    RoutedNetworkProtocolDataUnit::deserialize(&data[index..], channel)?;
                index = data.len() - remaining_data.len();
                Some(RoutingExtension::Routed(routing_extension))
            }
            MpduHeaderType::Explore => {
                let (explore_extension, remaining_data) =
                    ExploreNetworkProtocolDataUnit::deserialize(&data[index..])?;
                index = data.len() - remaining_data.len();
                Some(RoutingExtension::Explore(explore_extension))
            }
            _ => None,
        };

        let mpdu_bytes = data.get(0..mpdu_len_size).ok_or(ParseError::Incomplete)?;

        let payload_end = match speed {
            DataSpeed::Mesh100k | DataSpeed::LongRange100k => {
                // 16-bit CRC
                let (crc_bytes, expected_crc) = mpdu_bytes.split_at(mpdu_len_size - 2);
                let expected_crc = u16::from_be_bytes(expected_crc.try_into().unwrap());
                let calculated_crc = Self::crc_ccitt(crc_bytes);
                if calculated_crc == expected_crc {
                    mpdu.checksum = Some(CRCMode::CrcCcitt(calculated_crc));
                }

                mpdu_len_size.saturating_sub(2)
            }
            _ => {
                // xor 8-bit CRC
                let (crc_bytes, expected_crc) = mpdu_bytes.split_at(mpdu_len_size - 1);
                let expected_crc: u8 = expected_crc[0];
                let calculated_crc = Self::xor_checksum(crc_bytes);
                if calculated_crc == expected_crc {
                    mpdu.checksum = Some(CRCMode::XorChecksum(calculated_crc));
                }
                mpdu_len_size.saturating_sub(1)
            }
        };

        if index < payload_end {
            let payload = data
                .get(index..payload_end)
                .ok_or(ParseError::Incomplete)?
                .to_vec();
            mpdu.payload = Some(EncapsulationCommand::parse(
                payload.to_vec(),
                mpdu.source_node,
                &mpdu.destination,
                mpdu.home,
            ));
        }

        Ok((mpdu, &data[mpdu_len_size..]))
    }

    pub fn lr_deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, Self> {
        if data.is_empty() {
            return Err(ParseError::Empty);
        }
        let mut index: usize = 0;
        let mut mpdu = Self::default();

        let home_bytes = data.get(index..index + 4).ok_or(ParseError::Incomplete)?;
        mpdu.home = HomeId(u32::from_be_bytes(home_bytes.try_into().unwrap()));
        index += 4;

        let sender_and_receiver = data.get(index..index + 3).ok_or(ParseError::Incomplete)?;
        index += 3;

        mpdu.source_node =
            NodeId(((sender_and_receiver[0] as u16) << 4) | ((sender_and_receiver[1] >> 4) as u16));

        let dest =
            (((sender_and_receiver[1] & 0x0F) as u16) << 8) | (sender_and_receiver[2] as u16);

        mpdu.destination = match dest {
            0xFFF => Destination::Broadcast,
            _ => Destination::Single(NodeId(dest)),
        };

        let mpdu_len_size = *data.get(index).ok_or(ParseError::Incomplete)? as usize;
        index += 1;

        let frame_control = *data.get(index).ok_or(ParseError::Incomplete)?;
        let has_extension = frame_control & 0b0100_0000 != 0;
        mpdu.header_type = match (&mpdu.destination, &frame_control & 0b0000_0111) {
            (Destination::Broadcast, 0x01) => MpduHeaderType::Broadcast,
            (_, 0x3) => MpduHeaderType::Ack,
            _ => MpduHeaderType::Singlecast,
        };
        index += 1;

        mpdu.sequence_number = *data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;

        mpdu.noise_floor = Some(noise_floor_from_byte(
            *data.get(index).ok_or(ParseError::Incomplete)?,
        ));
        index += 1;

        mpdu.tx_power = Some(tx_power_from_byte(
            *data.get(index).ok_or(ParseError::Incomplete)?,
        ));
        index += 1;

        let mut mdsu_size = match mpdu.header_type {
            MpduHeaderType::Ack => mpdu_len_size.saturating_sub(15),
            _ => mpdu_len_size.saturating_sub(14),
        };

        if mpdu.header_type == MpduHeaderType::Ack {
            mpdu.incoming_rssi = Some(lr_rssi_from_byte(
                *data.get(index).ok_or(ParseError::Incomplete)?,
            ));
            index += 1;
        }

        if has_extension {
            let extension_control = *data.get(index).ok_or(ParseError::Incomplete)?;
            index += 1;

            // We're just going to ignore it for now
            let extension_data_length = (extension_control & 0b0000_0111) as usize;
            index += extension_data_length;
            mdsu_size = mdsu_size.saturating_sub(extension_data_length + 1);
        }

        if mdsu_size > 0 {
            mpdu.payload = Some(EncapsulationCommand::parse(
                data.get(index..index + mdsu_size)
                    .ok_or(ParseError::Incomplete)?
                    .to_vec(),
                mpdu.source_node,
                &mpdu.destination,
                mpdu.home,
            ));
            index += mdsu_size;
        }

        let expected_crc = data.get(index..index + 2).ok_or(ParseError::Incomplete)?;
        let expected_crc = u16::from_be_bytes(expected_crc.try_into().unwrap());
        let calculated_crc = Self::crc_ccitt(data.get(0..index).unwrap());
        index += 2;
        if calculated_crc == expected_crc {
            mpdu.checksum = Some(CRCMode::CrcCcitt(calculated_crc));
        }

        Ok((mpdu, &data[index..]))
    }

    pub fn mpdu_deserialize<'a>(
        data: &'a [u8],
        channel: &Channel,
        speed: &DataSpeed,
    ) -> ParseResult<'a, Self> {
        match channel {
            Channel::LongRangeA | Channel::LongRangeB => Self::lr_deserialize(data),
            _ => Self::mesh_deserialize(data, channel, speed),
        }
    }
}

// ==========================================
// Tests
// ==========================================

#[cfg(test)]
#[path = "mpdu_tests.rs"]
mod tests;
