use super::*;
use crate::frame::DataSpeed;
use crate::types::Channel;

#[test]
fn test_deserialize_singlecast() {
    let mpdu_bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41, 0x01, 0x0D, 0x01, 0x9F, 0x01, 0x2D, 0x76,
    ];
    let mpdu = Data::mpdu_deserialize(&mpdu_bytes, &Channel::Mesh2, &DataSpeed::Mesh40k)
        .unwrap()
        .0;
    assert_eq!(mpdu.home_id, HomeId(0xFDD09BC7));
    assert_eq!(mpdu.source_node_id, NodeId(7));
    assert_eq!(mpdu.header_type, MpduHeaderType::Singlecast);
    assert!(mpdu.ack_requested);
    assert!(!mpdu.low_power);
    assert!(!mpdu.speed_modified);
    assert_eq!(mpdu.sequence_number, 1);
    assert_eq!(mpdu.destination, Destination::Single(NodeId(1)));
    assert_eq!(mpdu.payload, Some(vec![0x9F, 0x01, 0x2D]));
}

#[test]
fn test_deserialize_singlecast_back_to_back() {
    let mpdu_bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41, 0x01, 0x0D, 0x01, 0x9F, 0x01, 0x2D, 0x76, 0xFD, 0xD0,
        0x9B, 0xC7, 0x07, 0x41, 0x01, 0x0D, 0x01, 0x9F, 0x01, 0x2D, 0x76,
    ];
    let (mpdu, next) =
        Data::mpdu_deserialize(&mpdu_bytes, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.home_id, HomeId(0xFDD09BC7));
    assert_eq!(mpdu.source_node_id, NodeId(7));
    assert_eq!(mpdu.header_type, MpduHeaderType::Singlecast);
    assert!(mpdu.ack_requested);
    assert!(!mpdu.low_power);
    assert!(!mpdu.speed_modified);
    assert_eq!(mpdu.sequence_number, 1);
    assert_eq!(mpdu.destination, Destination::Single(NodeId(1)));
    assert_eq!(*mpdu.payload.as_ref().unwrap(), vec![0x9F, 0x01, 0x2D]);

    // There's an exact copy still left. This wouldn't really happen, but it's easy to test.
    let (mpdu2, empty) =
        Data::mpdu_deserialize(next, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu, mpdu2);
    assert!(empty.is_empty());
}

#[test]
fn test_deserialize_empty() {
    assert_eq!(
        Data::mpdu_deserialize(&[], &Channel::Mesh2, &DataSpeed::Mesh40k),
        Err(ParseError::Empty)
    );
}

#[test]
fn test_deserialize_incomplete_header() {
    // Only 3 bytes (incomplete Home ID)
    assert_eq!(
        Data::mpdu_deserialize(&[0xFD, 0xD0, 0x9B], &Channel::Mesh2, &DataSpeed::Mesh40k),
        Err(ParseError::Incomplete)
    );
}

#[test]
fn test_deserialize_invalid_header_type() {
    // Frame Control 0 set to 0x4F (invalid header type 15)
    let bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x4F, 0x01, 0x0D, 0x01, 0x9F, 0x01, 0x2D, 0x76,
    ];
    assert_eq!(
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k),
        Err(ParseError::Invalid)
    );
}

#[test]
fn test_deserialize_length_too_short() {
    // Length set to 5 (minimum is 11 for singlecast)
    let bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41, 0x01, 0x05, 0x01, 0x9F, 0x01, 0x2D, 0x76,
    ];
    assert_eq!(
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k),
        Err(ParseError::Invalid)
    );
}

#[test]
fn test_deserialize_length_too_long() {
    // Length set to 100 (maximum is 65 for singlecast)
    let bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41, 0x01, 0x64, 0x01, 0x9F, 0x01, 0x2D, 0x76,
    ];
    assert_eq!(
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k),
        Err(ParseError::Invalid)
    );
}

#[test]
fn test_deserialize_truncated_payload() {
    // Length set to 13, but only 11 bytes provided in total
    let bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41, 0x01, 0x0D, 0x01, 0x9F, 0x01,
    ];
    assert_eq!(
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k),
        Err(ParseError::Invalid)
    );
}

#[test]
fn test_deserialize_invalid_checksum() {
    // Valid structure, but last byte (checksum) is 0x00 instead of 0x76
    let bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x07, 0x41, 0x01, 0x0D, 0x01, 0x9F, 0x01, 0x2D, 0x00,
    ];
    let (mpdu, _) = Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.checksum, None);
}

#[test]
fn test_deserialize_real_zniffer_data() {
    // Frame 1: Singlecast, Multi Channel Cmd Encap (100KBit/s)
    let frame1_bytes = vec![
        0xF9, 0xE0, 0xF2, 0x20, 0x01, 0x41, 0x06, 0x12, 0x06, 0x60, 0x0D, 0x01, 0x02, 0x25, 0x01,
        0xFF, 0x01, 0x82,
    ];
    let (mpdu1, remainder1) =
        Data::mpdu_deserialize(&frame1_bytes, &Channel::Mesh2, &DataSpeed::Mesh100k).unwrap();
    assert_eq!(mpdu1.home_id, HomeId(0xF9E0F220));
    assert_eq!(mpdu1.source_node_id, NodeId(1));
    assert_eq!(mpdu1.header_type, MpduHeaderType::Singlecast);
    assert!(mpdu1.ack_requested);
    assert_eq!(mpdu1.sequence_number, 6);
    assert_eq!(mpdu1.destination, Destination::Single(NodeId(6)));
    assert_eq!(
        mpdu1.payload,
        Some(vec![0x60, 0x0D, 0x01, 0x02, 0x25, 0x01, 0xFF])
    );
    assert_eq!(mpdu1.checksum, Some(CRCMode::CrcCcitt(0x0182)));
    assert!(remainder1.is_empty());

    // Frame 2: Ack (100KBit/s)
    let frame2_bytes = vec![
        0xF9, 0xE0, 0xF2, 0x20, 0x06, 0x03, 0x06, 0x0B, 0x01, 0x20, 0xD2,
    ];
    let (mpdu2, remainder2) =
        Data::mpdu_deserialize(&frame2_bytes, &Channel::Mesh2, &DataSpeed::Mesh100k).unwrap();
    assert_eq!(mpdu2.home_id, HomeId(0xF9E0F220));
    assert_eq!(mpdu2.source_node_id, NodeId(6));
    assert_eq!(mpdu2.header_type, MpduHeaderType::Ack);
    assert_eq!(mpdu2.sequence_number, 6);
    assert_eq!(mpdu2.destination, Destination::Single(NodeId(1)));
    assert!(mpdu2.payload.is_none());
    assert_eq!(mpdu2.checksum, Some(CRCMode::CrcCcitt(0x20D2)));
    assert!(remainder2.is_empty());

    // Frame 3: Singlecast, Switch Binary Report (100KBit/s)
    let frame3_bytes = vec![
        0xF9, 0xE0, 0xF2, 0x20, 0x06, 0x41, 0x05, 0x0E, 0x01, 0x25, 0x03, 0xFF, 0x83, 0xAE,
    ];
    let (mpdu3, remainder3) =
        Data::mpdu_deserialize(&frame3_bytes, &Channel::Mesh2, &DataSpeed::Mesh100k).unwrap();
    assert_eq!(mpdu3.home_id, HomeId(0xF9E0F220));
    assert_eq!(mpdu3.source_node_id, NodeId(6));
    assert_eq!(mpdu3.header_type, MpduHeaderType::Singlecast);
    assert_eq!(mpdu3.sequence_number, 5);
    assert_eq!(mpdu3.destination, Destination::Single(NodeId(1)));
    assert_eq!(mpdu3.payload, Some(vec![0x25, 0x03, 0xFF]));
    assert_eq!(mpdu3.checksum, Some(CRCMode::CrcCcitt(0x83AE)));
    assert!(remainder3.is_empty());

    // Frame 5: Singlecast, Meter Report (100KBit/s)
    let frame5_bytes = vec![
        0xF9, 0xE0, 0xF2, 0x20, 0x06, 0x41, 0x06, 0x15, 0x01, 0x32, 0x02, 0x21, 0x34, 0x00, 0x00,
        0x00, 0x54, 0x00, 0x00, 0x25, 0xCC,
    ];
    let (mpdu5, remainder5) =
        Data::mpdu_deserialize(&frame5_bytes, &Channel::Mesh2, &DataSpeed::Mesh100k).unwrap();
    assert_eq!(
        mpdu5.payload,
        Some(vec![
            0x32, 0x02, 0x21, 0x34, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00
        ])
    );
    assert_eq!(mpdu5.checksum, Some(CRCMode::CrcCcitt(0x25CC)));
    assert!(remainder5.is_empty());
}

#[test]
fn test_deserialize_routed_singlecast_extension() {
    use crate::types::RssiError;

    let mut bytes = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x81, 0x0B, 0x0F, 0x56, 0x00, 0x10, 0x03, 0x00,
    ];
    let calculated_crc = Data::crc_ccitt(&bytes);
    bytes.extend_from_slice(&calculated_crc.to_be_bytes());

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh100k).unwrap();

    assert_eq!(mpdu.home_id, HomeId(0xECEC74AB));
    assert_eq!(mpdu.source_node_id, NodeId(1));
    assert_eq!(mpdu.header_type, MpduHeaderType::Routed);
    assert!(!mpdu.ack_requested);
    assert_eq!(mpdu.sequence_number, 11);
    assert_eq!(mpdu.destination, Destination::Single(NodeId(86)));
    assert_eq!(mpdu.payload, Some(vec![0x00])); // NoOp command class
    assert_eq!(mpdu.checksum, Some(CRCMode::CrcCcitt(calculated_crc)));
    assert!(remainder.is_empty());

    assert_eq!(
        mpdu.routing_extension,
        Some(RoutingExtension::Routed(RoutedNetworkProtocolDataUnit {
            routed_result: None,
            failed_hop: None,
            repeaters: Some(vec![Hop {
                node_id: NodeId(3),
                rssi: Err(RssiError::NotAvailable),
            }]),
            beaming: None,
        }))
    );
}

#[test]
fn test_deserialize_extended_routing_header() {
    let mut bytes = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x81, 0x0B, 0x15, 0x56, 0x08, 0x20, 0x04, 0x05, 0x41, 0x14,
        0x1E, 0x7F, 0x7F, 0x00,
    ];
    let calculated_crc = Data::crc_ccitt(&bytes);
    bytes.extend_from_slice(&calculated_crc.to_be_bytes());

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh100k).unwrap();

    assert_eq!(mpdu.home_id, HomeId(0xECEC74AB));
    assert_eq!(mpdu.source_node_id, NodeId(1));
    assert_eq!(mpdu.header_type, MpduHeaderType::Routed);
    assert_eq!(mpdu.sequence_number, 11);
    assert_eq!(mpdu.destination, Destination::Single(NodeId(86)));
    assert_eq!(mpdu.payload, Some(vec![0x00]));
    assert_eq!(mpdu.checksum, Some(CRCMode::CrcCcitt(calculated_crc)));
    assert!(remainder.is_empty());

    assert_eq!(
        mpdu.routing_extension,
        Some(RoutingExtension::Routed(RoutedNetworkProtocolDataUnit {
            routed_result: None,
            failed_hop: None,
            repeaters: Some(vec![
                Hop {
                    node_id: NodeId(4),
                    rssi: Ok(20),
                },
                Hop {
                    node_id: NodeId(5),
                    rssi: Ok(30),
                },
            ]),
            beaming: None,
        }))
    );
}

#[test]
fn test_deserialize_channel3_routed_header() {
    use crate::types::RssiError;

    let mut bytes = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x08, 0x00, 0x11, 0x0B, 0x56, 0x00, 0x10, 0x03, 0x00, 0x00,
    ];
    let calculated_crc = Data::crc_ccitt(&bytes);
    bytes.extend_from_slice(&calculated_crc.to_be_bytes());

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&bytes, &Channel::Mesh3, &DataSpeed::Mesh100k).unwrap();

    assert_eq!(mpdu.home_id, HomeId(0xECEC74AB));
    assert_eq!(mpdu.source_node_id, NodeId(1));
    assert_eq!(mpdu.header_type, MpduHeaderType::Routed);
    assert_eq!(mpdu.sequence_number, 11);
    assert_eq!(mpdu.destination, Destination::Single(NodeId(86)));
    assert_eq!(mpdu.payload, Some(vec![0x00]));
    assert_eq!(mpdu.checksum, Some(CRCMode::CrcCcitt(calculated_crc)));
    assert!(remainder.is_empty());

    assert_eq!(
        mpdu.routing_extension,
        Some(RoutingExtension::Routed(RoutedNetworkProtocolDataUnit {
            routed_result: None,
            failed_hop: None,
            repeaters: Some(vec![Hop {
                node_id: NodeId(3),
                rssi: Err(RssiError::NotAvailable),
            }]),
            beaming: None,
        }))
    );
}

#[test]
fn test_deserialize_explorer_normal() {
    // 50  11:34:18.427    40Kbit/s    99  1   Explorer Normal CRC16 Encap F22FC1AB63450319012000FA400000000056012503FF795840
    let bytes1 = vec![
        0xF2, 0x2F, 0xC1, 0xAB, 0x63, 0x45, 0x03, 0x19, 0x01, 0x20, 0x00, 0xFA, 0x40, 0x00, 0x00,
        0x00, 0x00, 0x56, 0x01, 0x25, 0x03, 0xFF, 0x79, 0x58, 0x40,
    ];
    let (mpdu1, remainder1) =
        Data::mpdu_deserialize(&bytes1, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu1.home_id, HomeId(0xF22FC1AB));
    assert_eq!(mpdu1.source_node_id, NodeId(99));
    assert_eq!(mpdu1.header_type, MpduHeaderType::Explore);
    assert!(mpdu1.ack_requested);
    assert_eq!(mpdu1.sequence_number, 3);
    assert_eq!(mpdu1.destination, Destination::Single(NodeId(1)));
    assert_eq!(
        mpdu1.payload,
        Some(vec![0x56, 0x01, 0x25, 0x03, 0xFF, 0x79, 0x58])
    );
    assert_eq!(mpdu1.checksum, Some(CRCMode::XorChecksum(0x40)));
    assert!(remainder1.is_empty());

    if let Some(RoutingExtension::Explore(ext1)) = mpdu1.routing_extension {
        assert_eq!(ext1.command, ExplorerPayload::Normal);
        assert_eq!(ext1.direction, ExplorerDirection::Outbound);
        assert_eq!(ext1.random_tx_interval, 250);
        assert_eq!(ext1.repeaters, None);
    } else {
        panic!("Expected Explore routing extension");
    }

    // 51  11:34:18.481    40Kbit/s    99  1   Explorer Normal CRC16 Encap F22FC1AB63450319012000FA311E00000056012503FF79582F
    let bytes2 = vec![
        0xF2, 0x2F, 0xC1, 0xAB, 0x63, 0x45, 0x03, 0x19, 0x01, 0x20, 0x00, 0xFA, 0x31, 0x1E, 0x00,
        0x00, 0x00, 0x56, 0x01, 0x25, 0x03, 0xFF, 0x79, 0x58, 0x2F,
    ];
    let (mpdu2, remainder2) =
        Data::mpdu_deserialize(&bytes2, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu2.home_id, HomeId(0xF22FC1AB));
    assert_eq!(mpdu2.source_node_id, NodeId(99));
    assert_eq!(mpdu2.header_type, MpduHeaderType::Explore);
    assert!(mpdu2.ack_requested);
    assert_eq!(mpdu2.sequence_number, 3);
    assert_eq!(mpdu2.destination, Destination::Single(NodeId(1)));
    assert_eq!(
        mpdu2.payload,
        Some(vec![0x56, 0x01, 0x25, 0x03, 0xFF, 0x79, 0x58])
    );
    assert_eq!(mpdu2.checksum, Some(CRCMode::XorChecksum(0x2F)));
    assert!(remainder2.is_empty());

    if let Some(RoutingExtension::Explore(ext2)) = mpdu2.routing_extension {
        assert_eq!(ext2.command, ExplorerPayload::Normal);
        assert_eq!(ext2.direction, ExplorerDirection::Outbound);
        assert_eq!(ext2.random_tx_interval, 250);
        assert_eq!(ext2.repeaters, Some(vec![NodeId(30)]));
    } else {
        panic!("Expected Explore routing extension");
    }
}

#[test]
fn test_deserialize_singlecast_node8() {
    let mpdu_bytes = vec![
        0xFD, 0xD0, 0x9B, 0xC7, 0x01, 0x41, 0x04, 0x0B, 0x08, 0x00, 0xC9,
    ];
    let (mpdu, remainder) =
        Data::mpdu_deserialize(&mpdu_bytes, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.home_id, HomeId(0xFDD09BC7));
    assert_eq!(mpdu.source_node_id, NodeId(1));
    assert_eq!(mpdu.header_type, MpduHeaderType::Singlecast);
    assert!(mpdu.ack_requested);
    assert!(!mpdu.low_power);
    assert!(!mpdu.speed_modified);
    assert_eq!(mpdu.sequence_number, 4);
    assert_eq!(mpdu.destination, Destination::Single(NodeId(8)));
    assert_eq!(mpdu.payload, Some(vec![0x00]));
    assert_eq!(mpdu.checksum, Some(CRCMode::XorChecksum(0xC9)));
    assert!(remainder.is_empty());
}

#[test]
fn test_deserialize_multicast() {
    let mut data = vec![
        0x12, 0x34, 0x56, 0x78, // Home ID
        0x03, // Source Node ID (3)
        0x02, // Frame Control 0 (HeaderType: Multicast)
        0x01, // Frame Control 1 (Sequence number 1)
        41,   // Length
        0x03, // Mask Header (offset=0, mask_len=3)
        0x01, 0x02, 0x80, // Mask bytes: Node 1, Node 10, Node 24
    ];
    data.resize(40, 0x00);
    // XOR checksum
    let xor = data.iter().fold(0u8, |acc, &x| acc ^ x);
    data.push(xor);

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&data, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.home_id, HomeId(0x12345678));
    assert_eq!(mpdu.source_node_id, NodeId(3));
    assert_eq!(mpdu.header_type, MpduHeaderType::Multicast);
    assert_eq!(mpdu.sequence_number, 1);

    if let Destination::Multicast(ref nodes) = mpdu.destination {
        assert_eq!(nodes.len(), 3);
        assert!(nodes.contains(&NodeId(1)));
        assert!(nodes.contains(&NodeId(10)));
        assert!(nodes.contains(&NodeId(24)));
    }
    assert!(remainder.is_empty());
}

#[test]
fn test_deserialize_multicast_forum_report() {
    let data = vec![
        0xEF, 0xF5, 0x37, 0xA2, // Home ID
        0x49, // Source Node ID (73)
        0x02, // Frame Control 0 (HeaderType: Multicast)
        0x01, // Frame Control 1 (Sequence number 1)
        0x30, // Length (48)
        0x1D, // Mask Header (offset=0, mask_len=29)
        // 29 mask bytes:
        0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Payload (9 bytes)
        0x71, 0x05, 0x00, 0x00, 0x00, 0xFF, 0x07, 0x08, 0x00, // Checksum
        0xB2,
    ];

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&data, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.home_id, HomeId(0xEFF537A2));
    assert_eq!(mpdu.source_node_id, NodeId(73));
    assert_eq!(mpdu.header_type, MpduHeaderType::Multicast);
    assert_eq!(mpdu.sequence_number, 1);
    assert_eq!(mpdu.checksum, Some(CRCMode::XorChecksum(0xB2)));

    if let Destination::Multicast(ref nodes) = mpdu.destination {
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId(1)));
        assert!(nodes.contains(&NodeId(30)));
    } else {
        panic!("Expected Destination::Multicast");
    }
    assert_eq!(
        mpdu.payload,
        Some(vec![0x71, 0x05, 0x00, 0x00, 0x00, 0xFF, 0x07, 0x08, 0x00])
    );
    assert!(remainder.is_empty());
}

#[test]
fn test_deserialize_invalid_crc16() {
    let mut bytes = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x08, 0x00, 0x11, 0x0B, 0x56, 0x00, 0x10, 0x03, 0x00, 0x00,
    ];
    let calculated_crc = Data::crc_ccitt(&bytes);
    // Add corrupted CRC16 byte (e.g. calculated_crc ^ 1)
    bytes.extend_from_slice(&(calculated_crc ^ 1).to_be_bytes());

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&bytes, &Channel::Mesh3, &DataSpeed::Mesh100k).unwrap();

    assert_eq!(mpdu.checksum, None);
    assert!(remainder.is_empty());
}

#[test]
fn test_routed_npdu_too_many_repeaters() {
    let mut bytes = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x08, 0x00, 0x11, 0x0B, 0x56,
        0x00, // first byte of RoutedNPDU
        0x50, // second byte: num_repeaters = 5
        0x01, 0x02, 0x03, 0x04, 0x05, // 5 repeaters
        0x03, // payload
    ];
    let calculated_crc = Data::crc_ccitt(&bytes);
    bytes.extend_from_slice(&calculated_crc.to_be_bytes());

    let res = Data::mpdu_deserialize(&bytes, &Channel::Mesh3, &DataSpeed::Mesh100k);
    assert!(matches!(res, Err(ParseError::Invalid)));
}

#[test]
fn test_explorer_invalid_version() {
    let bytes = vec![
        0xF2, 0x2F, 0xC1, 0xAB, 0x63, 0x45, 0x03, 0x19, 0x01, // dest node id
        0x40, // Explorer extension byte 1 (version 2, command 0)
        0x00, 0xFA, 0x40, 0x00, 0x00, 0x00, 0x00, 0x56, 0x01, 0x25, 0x03, 0xFF, 0x79, 0x58, 0x40,
    ];
    let res = Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k);
    assert!(matches!(res, Err(ParseError::Invalid)));
}

#[test]
fn test_explorer_inbound_inclusion_info() {
    let mut bytes = vec![
        0xF2, 0x2F, 0xC1, 0xAB, // Home ID
        0x63, // Source ID
        0x45, 0x03, // Frame Control
        23,   // Length
        0x01, // Dest Node ID
        0x21, // First byte (version 1, command 1 = InclusionInformation)
        0x02, // Second byte (direction = Inbound)
        0x05, // Third byte (random_tx_interval)
        0x00, // Fourth byte (ignored repeater count)
        0x00, 0x00, 0x00, 0x00, // Repeaters (none)
        0x11, 0x22, 0x33, 0x44, // Home ID in Inclusion Information payload
        0x99, // Payload byte
    ];
    let xor = bytes.iter().fold(0u8, |acc, &x| acc ^ x);
    bytes.push(xor);

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.header_type, MpduHeaderType::Explore);
    assert!(remainder.is_empty());

    if let Some(RoutingExtension::Explore(ref exp)) = mpdu.routing_extension {
        assert_eq!(exp.direction, ExplorerDirection::Inbound);
        assert_eq!(exp.random_tx_interval, 5);
        assert_eq!(exp.repeaters, None);
        assert_eq!(
            exp.command,
            ExplorerPayload::InclusionInformation {
                home_id: Some(HomeId(0x11223344))
            }
        );
    } else {
        panic!("Expected RoutingExtension::Explore");
    }
}

#[test]
fn test_explorer_search_command() {
    let mut bytes = vec![
        0xF2, 0x2F, 0xC1, 0xAB, // Home ID
        0x63, // Source ID
        0x45, 0x03, // Frame Control
        26,   // Length
        0x01, // Dest Node ID
        0x22, // First byte (version 1, command 2 = Search)
        0x00, // Second byte (direction = Outbound)
        0x05, // Third byte (random_tx_interval)
        0x00, // Fourth byte (ignored repeater count)
        0x03, 0x04, 0x00, 0x00, // Repeaters: Node 3, Node 4
        0x07, // Search source_node_id = 7
        0x0E, // Search frame_handle = 14
        0x00, // TTL / result repeater count (ignored)
        0x01, 0x02, 0x00, 0x00, // Result repeaters: Node 1, Node 2
        0x99, // Payload byte
    ];
    let xor = bytes.iter().fold(0u8, |acc, &x| acc ^ x);
    bytes.push(xor);

    let (mpdu, remainder) =
        Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    assert_eq!(mpdu.header_type, MpduHeaderType::Explore);
    assert!(remainder.is_empty());

    if let Some(RoutingExtension::Explore(ref exp)) = mpdu.routing_extension {
        assert_eq!(exp.direction, ExplorerDirection::Outbound);
        assert_eq!(exp.random_tx_interval, 5);
        assert_eq!(exp.repeaters, Some(vec![NodeId(3), NodeId(4)]));
        assert_eq!(
            exp.command,
            ExplorerPayload::Search {
                source_node_id: NodeId(7),
                frame_handle: 14,
                result_repeaters: vec![NodeId(1), NodeId(2)]
            }
        );
    } else {
        panic!("Expected RoutingExtension::Explore");
    }
}

#[test]
fn test_explorer_inclusion_info_zero_home_id() {
    let mut bytes = vec![
        0xF2, 0x2F, 0xC1, 0xAB, 0x63, 0x45, 0x03, 23, 0x01, 0x21, 0x02, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Home ID = 0
        0x99,
    ];
    let xor = bytes.iter().fold(0u8, |acc, &x| acc ^ x);
    bytes.push(xor);

    let (mpdu, _) = Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k).unwrap();
    if let Some(RoutingExtension::Explore(ref exp)) = mpdu.routing_extension {
        assert_eq!(
            exp.command,
            ExplorerPayload::InclusionInformation { home_id: None }
        );
    } else {
        panic!("Expected RoutingExtension::Explore");
    }
}

#[test]
fn test_explorer_invalid_command() {
    let bytes = vec![
        0xF2, 0x2F, 0xC1, 0xAB, 0x63, 0x45, 0x03, 0x19, 0x01, 0x23, // command = 3 (invalid)
        0x00, 0xFA, 0x40, 0x00, 0x00, 0x00, 0x00, 0x56, 0x01, 0x25, 0x03, 0xFF, 0x79, 0x58, 0x40,
    ];
    let res = Data::mpdu_deserialize(&bytes, &Channel::Mesh2, &DataSpeed::Mesh40k);
    assert!(matches!(res, Err(ParseError::Invalid)));
}

#[test]
fn test_routed_npdu_invalid_extended_header() {
    let mut bytes = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x08, 0x00, 0x11, 0x0B, 0x56,
        0x08, // first byte: extended header available
        0x00, // second byte: 0 repeaters
        0x20, // header_info: len=2, type=0 (invalid)
        0x00, 0x00, // 2 bytes payload
        0x03, // payload
    ];
    let calculated_crc = Data::crc_ccitt(&bytes);
    bytes.extend_from_slice(&calculated_crc.to_be_bytes());

    let res = Data::mpdu_deserialize(&bytes, &Channel::Mesh3, &DataSpeed::Mesh100k);
    assert!(matches!(res, Err(ParseError::Invalid)));
}

#[test]
fn test_routed_npdu_beaming_extension() {
    // Test Long Beaming (0b0100_0000 -> 0x40)
    let mut bytes_long = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x08, 0x00, 0x12, // length = 18 (0x12)
        0x0B, 0x56, 0x08, // first byte: extended header available
        0x00, // second byte: 0 repeaters
        0x00, // dest_wakeup_data (Mesh3 specific byte)
        0x10, // header_info: len=1, type=0 (beaming)
        0x40, // beaming_extension: Long
        0x03, // payload
    ];
    let calculated_crc = Data::crc_ccitt(&bytes_long);
    bytes_long.extend_from_slice(&calculated_crc.to_be_bytes());

    let (mpdu_long, _) =
        Data::mpdu_deserialize(&bytes_long, &Channel::Mesh3, &DataSpeed::Mesh100k).unwrap();
    if let Some(RoutingExtension::Routed(ref routed)) = mpdu_long.routing_extension {
        assert_eq!(routed.beaming, Some(BeamingType::Long));
    } else {
        panic!("Expected RoutingExtension::Routed");
    }

    // Test Short Beaming (0b0010_0000 -> 0x20)
    let mut bytes_short = vec![
        0xEC, 0xEC, 0x74, 0xAB, 0x01, 0x08, 0x00, 0x12, // length = 18 (0x12)
        0x0B, 0x56, 0x08, 0x00, 0x00, // dest_wakeup_data (Mesh3 specific byte)
        0x10, 0x20, // beaming_extension: Short
        0x03,
    ];
    let calculated_crc = Data::crc_ccitt(&bytes_short);
    bytes_short.extend_from_slice(&calculated_crc.to_be_bytes());

    let (mpdu_short, _) =
        Data::mpdu_deserialize(&bytes_short, &Channel::Mesh3, &DataSpeed::Mesh100k).unwrap();
    if let Some(RoutingExtension::Routed(ref routed)) = mpdu_short.routing_extension {
        assert_eq!(routed.beaming, Some(BeamingType::Short));
    } else {
        panic!("Expected RoutingExtension::Routed");
    }
}
