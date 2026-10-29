// SPDX-License-Identifier: LGPL-3.0-or-later

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisionGetEncapsulation {
    pub status_updates: bool,
    pub session: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiChannelEncapsulation {
    pub source_endpoint: u8,
    pub destination_endpoints: Vec<u8>,
}
