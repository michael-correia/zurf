// SPDX-License-Identifier: LGPL-3.0-or-later

use zurf_enum_derive::TryFromU8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HomeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeId(pub u16);

impl NodeId {
    pub fn is_broadcast(&self) -> bool {
        self.0 == 0xFF || self.0 == 0x0FFF
    }
}

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssiError {
    TooLow = 0x7D,
    Saturation = 0x7E,
    NotAvailable = 0x7F,
}

pub type Rssi = Result<i8, RssiError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    pub node_id: NodeId,
    pub rssi: Rssi,
}

impl Hop {
    pub fn rssi_from_byte(byte: u8) -> Rssi {
        match byte {
            0x7D => Err(RssiError::TooLow),
            0x7E => Err(RssiError::Saturation),
            0x7F => Err(RssiError::NotAvailable),
            _ => Ok(byte as i8),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    Incomplete,
    Invalid,
}

pub type ParseResult<'a, T> = std::result::Result<(T, &'a [u8]), ParseError>;

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Mesh1 = 0,
    Mesh2 = 1,
    Mesh3 = 2,
    LongRangeA = 3,
    LongRangeB = 4,
}

impl Channel {
    pub fn is_long_range(&self) -> bool {
        matches!(self, Channel::LongRangeA | Channel::LongRangeB)
    }
}
