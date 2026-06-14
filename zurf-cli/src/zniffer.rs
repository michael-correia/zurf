// SPDX-License-Identifier: GPL-3.0-or-later

use crate::transport::IoUringUART;
use zurf::frame::Frame;
use zurf::parser::Parser;

pub struct Zniffer {
    parser: Parser,
    transport: IoUringUART,
}

impl Zniffer {
    pub fn new(parser: Parser, transport: IoUringUART) -> Self {
        Self { parser, transport }
    }

    pub fn next_frame(&mut self) -> std::io::Result<Vec<Frame>> {
        self.transport.next_frame(&mut self.parser)
    }
}
