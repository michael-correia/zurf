// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::{
    mpdu::Data,
    types::{Channel, DataSpeed, Hop, NodeId, ParseError, ParseResult, Rssi},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeamStart {
    pub node: NodeId,
    pub home_hash: u8,
}

impl DeserializeFrame for BeamStart {
    fn deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, (Self, FrameParseMetadata)> {
        let mut index = 2;
        let channel_speed = data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;

        let data_speed =
            DataSpeed::try_from(channel_speed & 0x1F).map_err(|_| ParseError::Invalid)?;
        let channel = Some(Channel::try_from(channel_speed >> 5).map_err(|_| ParseError::Invalid)?);

        // skip region
        index += 1;

        let rssi = Hop::rssi_from_byte(*data.get(index).ok_or(ParseError::Incomplete)?);
        index += 1;

        let marker = *data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;
        if marker != 0x55 {
            return Err(ParseError::Invalid);
        }

        let node = *data.get(index).ok_or(ParseError::Incomplete)? as u16;
        index += 1;

        let node = if data_speed.is_long_range() {
            NodeId(node + 255)
        } else {
            NodeId(node)
        };

        let marker = *data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;
        if marker != 0x01 {
            return Err(ParseError::Invalid);
        }

        let home_hash = *data.get(index).ok_or(ParseError::Incomplete)?;
        index += 1;

        Ok((
            (
                Self { node, home_hash },
                FrameParseMetadata {
                    data_speed: Some(data_speed),
                    channel,
                    rssi,
                },
            ),
            &data[index..],
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeamEnd {
    pub counter: u16,
}

impl DeserializeFrame for BeamEnd {
    fn deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, (Self, FrameParseMetadata)> {
        let mut index = 2;

        let rssi = Hop::rssi_from_byte(*data.get(index).ok_or(ParseError::Incomplete)?);
        index += 1;

        let counter_bytes: [u8; 2] = data
            .get(index..index + 2)
            .ok_or(ParseError::Incomplete)?
            .try_into()
            .map_err(|_| ParseError::Invalid)?;
        index += 2;

        let counter = u16::from_be_bytes(counter_bytes);

        Ok((
            (
                Self { counter },
                FrameParseMetadata {
                    data_speed: None,
                    channel: None,
                    rssi,
                },
            ),
            &data[index..],
        ))
    }
}

impl DeserializeFrame for Data {
    fn deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, (Self, FrameParseMetadata)> {
        // Rather than just returning incomplete length up-front, return validation errors first so that we can return to the SOF hunt
        if data.is_empty() {
            return Err(ParseError::Empty);
        }

        // Timestamp hardcoded to 0, ignore it instead of validating in case it ever gets populated
        let (_, data) = data.split_at_checked(2).ok_or(ParseError::Incomplete)?;

        let (&channel_speed, data) = data.split_first().ok_or(ParseError::Incomplete)?;

        let data_speed =
            DataSpeed::try_from(channel_speed & 0x1F).map_err(|_| ParseError::Invalid)?;

        let channel = Channel::try_from(channel_speed >> 5).map_err(|_| ParseError::Invalid)?;

        if channel.is_long_range() != data_speed.is_long_range() {
            return Err(ParseError::Invalid);
        }

        // Ignore region - Already know it from radio configuration
        let (&_, data) = data.split_first().ok_or(ParseError::Incomplete)?;

        let (&rssi, data) = data.split_first().ok_or(ParseError::Incomplete)?;
        let rssi = Hop::rssi_from_byte(rssi);

        let (start_of_data_marker, data) =
            data.split_at_checked(2).ok_or(ParseError::Incomplete)?;
        if start_of_data_marker != [0x21, 0x03] {
            return Err(ParseError::Invalid);
        }

        let (&len, data) = data.split_first().ok_or(ParseError::Incomplete)?;
        let len = len as usize;
        if len > data.len() {
            return Err(ParseError::Incomplete);
        }
        let (mpdu_bytes, _) = data.split_at(len);
        let (mpdu, rest) = Data::mpdu_deserialize(mpdu_bytes, &channel, &data_speed)?;

        Ok((
            (
                mpdu,
                FrameParseMetadata {
                    data_speed: Some(data_speed),
                    channel: Some(channel),
                    rssi,
                },
            ),
            rest,
        ))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Markers {
    StartOfFrame = 0x21,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    //Command { cmd: u8, len: u8, payload: Vec<u8> } = 0x00, // We'll ignored command so we can create metadata struct
    Data(Box<Data>) = 0x01,
    BeamStart(BeamStart) = 0x04,
    BeamEnd(BeamEnd) = 0x05,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub timestamp: std::time::SystemTime,
    pub data_speed: Option<DataSpeed>,
    pub channel: Option<Channel>,
    pub rssi: Rssi,
    pub payload: FrameType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameParseMetadata {
    pub data_speed: Option<DataSpeed>,
    pub channel: Option<Channel>,
    pub rssi: Rssi,
}

impl Frame {
    pub fn deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, Self> {
        let (sof, rest) = data.split_first().ok_or(ParseError::Incomplete)?;
        if *sof != Markers::StartOfFrame as u8 {
            return Err(ParseError::Invalid);
        }

        let (frame_type, rest) = rest.split_first().ok_or(ParseError::Incomplete)?;

        let (payload, metadata, rest) = match *frame_type {
            0x01 => {
                let ((inner, meta), rest) = Data::deserialize(rest)?;
                (FrameType::Data(Box::new(inner)), meta, rest)
            }
            0x04 => {
                let ((inner, meta), rest) = BeamStart::deserialize(rest)?;
                (FrameType::BeamStart(inner), meta, rest)
            }
            0x05 => {
                let ((inner, meta), rest) = BeamEnd::deserialize(rest)?;
                (FrameType::BeamEnd(inner), meta, rest)
            }
            _ => return Err(ParseError::Invalid),
        };

        let frame = Frame {
            timestamp: std::time::SystemTime::now(),
            data_speed: metadata.data_speed,
            channel: metadata.channel,
            rssi: metadata.rssi,
            payload,
        };

        Ok((frame, rest))
    }
}

trait DeserializeFrame: Sized {
    fn deserialize<'a>(data: &'a [u8]) -> ParseResult<'a, (Self, FrameParseMetadata)>;
}

#[cfg(test)]
mod tests {

    use crate::{
        frame::{BeamEnd, BeamStart, DataSpeed, DeserializeFrame},
        mpdu::Data,
        types::{Channel, NodeId, ParseError},
    }; // Give tests access to everything in the file

    #[test]
    fn data_frame_parse_ok() {
        let data = vec![
            0x00, 0x00, 0x21, 0x09, 0x2F, 0x21, 0x03, 0x0D, 0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41,
            0x01, 0x0D, 0x01, 0x9F, 0x01, 0x2D, 0x76,
        ];
        assert!(Data::deserialize(&data).is_ok());
    }

    #[test]
    fn data_frame_empty() {
        assert!(matches!(Data::deserialize(&[]), Err(ParseError::Empty)));
    }

    #[test]
    fn data_frame_truncated_timestamp() {
        // Only 1 byte — need 2 for timestamp
        assert!(matches!(
            Data::deserialize(&[0x00]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_truncated_channel_speed() {
        // Timestamp only, no channel_speed byte
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_invalid_speed() {
        // channel_speed = 0x1F → speed = 31, no such DataSpeed variant
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x1F]),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn data_frame_invalid_channel() {
        // channel_speed = 0xE1 → channel = 7 (0xE1 >> 5), no such Channel variant
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0xE1]),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn data_frame_truncated_region() {
        // Valid channel_speed but no region byte
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x21]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_truncated_rssi() {
        // Has region but no RSSI
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x21, 0x09]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_truncated_sodm() {
        // Has RSSI but only 1 of 2 SODM bytes
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x21, 0x09, 0x2F, 0x21]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_invalid_sodm() {
        // Wrong start-of-data marker
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x21, 0x09, 0x2F, 0x00, 0x00]),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn data_frame_truncated_length() {
        // Correct SODM but no length byte
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x21, 0x09, 0x2F, 0x21, 0x03]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_payload_too_short() {
        // Length says 5 bytes but 0 bytes of payload follow
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x21, 0x09, 0x2F, 0x21, 0x03, 0x05]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn data_frame_lr_channel_mesh_speed() {
        // channel = 3 (LongRangeA), speed = 0 (Mesh9600) → mismatch
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x60]),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn data_frame_mesh_channel_lr_speed() {
        // channel = 0 (Mesh1), speed = 3 (LongRange100k) → mismatch
        assert!(matches!(
            Data::deserialize(&[0x00, 0x00, 0x03]),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn beam_start_standard_ok() {
        // Standard Z-Wave Beam Start payload:
        // [0x00, 0x00]: Timestamp
        // 0x21: Channel=Mesh2 (1), Speed=Mesh40k (1) -> (1 << 5) | 1 = 33 = 0x21
        // 0x09: Region
        // 0x2F: RSSI (47 dBm)
        // 0x55: Marker
        // 0x08: Destination Node ID (Node 8)
        // 0x01: Marker
        // 0x2D: Home ID Hash
        let data = vec![0x00, 0x00, 0x21, 0x09, 0x2F, 0x55, 0x08, 0x01, 0x2D];
        let parsed = BeamStart::deserialize(&data);
        assert!(parsed.is_ok());
        let (beam, metadata) = parsed.unwrap().0;
        assert_eq!(beam.node, NodeId(8));
        assert_eq!(beam.home_hash, 0x2D);
        assert_eq!(metadata.data_speed, Some(DataSpeed::Mesh40k));
        assert_eq!(metadata.channel, Some(Channel::Mesh2));
        assert_eq!(metadata.rssi, Ok(47));
    }

    #[test]
    fn beam_start_long_range_ok() {
        // Z-Wave Long Range Beam Start payload matching firmware bug:
        // [0x00, 0x00]: Timestamp
        // 0x63: Channel=LongRangeA (3), Speed=LongRange100k (3) -> (3 << 5) | 3 = 99 = 0x63
        // 0x09: Region
        // 0x2F: RSSI
        // 0x55: Marker
        // 0x03: Truncated Node ID (e.g. Node 259 & 0xFF = 3)
        // 0x01: Hardcoded Marker
        // 0x2D: Home ID Hash
        let data = vec![0x00, 0x00, 0x63, 0x09, 0x2F, 0x55, 0x03, 0x01, 0x2D];
        let parsed = BeamStart::deserialize(&data);
        assert!(parsed.is_ok());
        let (beam, metadata) = parsed.unwrap().0;
        assert_eq!(beam.node, NodeId(258));
        assert_eq!(beam.home_hash, 0x2D);
        assert_eq!(metadata.data_speed, Some(DataSpeed::LongRange100k));
        assert_eq!(metadata.channel, Some(Channel::LongRangeA));
        assert_eq!(metadata.rssi, Ok(47));
    }

    #[test]
    fn beam_end_ok() {
        // Raw frame: [0x21, 0x05, 0x00, 0x00, 0x30, 0x00, 0xE7]
        // Payload passed to deserialize starts after SOF and Type:
        // [0x00, 0x00, 0x30, 0x00, 0xE7]
        let data = vec![0x00, 0x00, 0x30, 0x00, 0xE7];
        let parsed = BeamEnd::deserialize(&data);
        assert!(parsed.is_ok());
        let (beam, metadata) = parsed.unwrap().0;
        assert_eq!(beam.counter, 0x00E7);
        assert_eq!(metadata.rssi, Ok(48)); // 0x30 is 48
    }

    #[test]
    fn test_frame_invalid_sof() {
        let data = vec![0x00, 0x05, 0x00, 0x00, 0x30, 0x00, 0xE7];
        assert!(matches!(
            crate::frame::Frame::deserialize(&data),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn test_frame_invalid_type() {
        let data = vec![0x21, 0x99, 0x00, 0x00, 0x30, 0x00, 0xE7];
        assert!(matches!(
            crate::frame::Frame::deserialize(&data),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn test_frame_truncated() {
        assert!(matches!(
            crate::frame::Frame::deserialize(&[]),
            Err(ParseError::Incomplete)
        ));
        assert!(matches!(
            crate::frame::Frame::deserialize(&[0x21]),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_beam_start_invalid_speed_channel() {
        // bad speed (0x1F)
        let data = vec![0x00, 0x00, 0x1F, 0x09, 0x2F, 0x55, 0x08, 0x01, 0x2D];
        assert!(matches!(
            BeamStart::deserialize(&data),
            Err(ParseError::Invalid)
        ));

        // bad channel (0xE1 -> channel 7)
        let data2 = vec![0x00, 0x00, 0xE1, 0x09, 0x2F, 0x55, 0x08, 0x01, 0x2D];
        assert!(matches!(
            BeamStart::deserialize(&data2),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn test_beam_start_invalid_markers() {
        // bad 0x55 marker (0x00 instead)
        let data = vec![0x00, 0x00, 0x21, 0x09, 0x2F, 0x00, 0x08, 0x01, 0x2D];
        assert!(matches!(
            BeamStart::deserialize(&data),
            Err(ParseError::Invalid)
        ));

        // bad 0x01 marker (0x00 instead)
        let data2 = vec![0x00, 0x00, 0x21, 0x09, 0x2F, 0x55, 0x08, 0x00, 0x2D];
        assert!(matches!(
            BeamStart::deserialize(&data2),
            Err(ParseError::Invalid)
        ));
    }

    #[test]
    fn test_beam_start_truncations() {
        let base = vec![0x00, 0x00, 0x21, 0x09, 0x2F, 0x55, 0x08, 0x01, 0x2D];
        for len in 0..base.len() {
            assert!(matches!(
                BeamStart::deserialize(&base[..len]),
                Err(ParseError::Incomplete)
            ));
        }
    }

    #[test]
    fn test_beam_end_truncations() {
        let base = [0x00, 0x00, 0x30, 0x00, 0xE7];
        for len in 0..base.len() {
            assert!(matches!(
                BeamEnd::deserialize(&base[..len]),
                Err(ParseError::Incomplete)
            ));
        }
    }
}
