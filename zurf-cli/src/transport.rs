// SPDX-License-Identifier: GPL-3.0-or-later

use io_uring::{IoUring, opcode};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

use zurf::frame::Frame;
use zurf::parser::Parser;
use zurf::types::ParseError;

pub struct IoUringUART {
    port: std::fs::File,
    ring: IoUring,
    buf: [u8; 2048],
    frame_start: usize,
    parse_idx: usize,
    valid_len: usize,
}

impl IoUringUART {
    /// Opens and configures the serial port, performs baud rate detection,
    /// sets the Zniffer region, and initializes the `io_uring` reader.
    pub fn new(port_name: &str, region: u8) -> std::io::Result<Self> {
        let mut port = Self::prepare_port(port_name, libc::B115200, region);
        if port.is_err() {
            port = Self::prepare_port(port_name, libc::B230400, region);
        }
        let port = port?;
        let ring = IoUring::new(8)?;

        Ok(Self {
            port,
            ring,
            buf: [0; 2048],
            frame_start: 0,
            parse_idx: 0,
            valid_len: 0,
        })
    }

    fn prepare_port(
        port_name: &str,
        baud_rate: libc::speed_t,
        region: u8,
    ) -> std::io::Result<std::fs::File> {
        let mut port = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(port_name)?;

        unsafe {
            let fd = port.as_raw_fd();
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);

            let mut tty: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut tty) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::cfsetospeed(&mut tty, baud_rate);
            libc::cfsetispeed(&mut tty, baud_rate);

            tty.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHOE | libc::ISIG);
            tty.c_iflag &= !(libc::IXON | libc::IXOFF | libc::IXANY);
            tty.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::PARMRK
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL);

            tty.c_cc[libc::VTIME] = 1;
            tty.c_cc[libc::VMIN] = 1;
            if libc::tcsetattr(fd, libc::TCSANOW, &tty) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        // Set Region Command
        port.write_all(&[0x23, 0x02, 0x01, region])?;

        let mut serial_buf: Vec<u8> = vec![0; 32];
        for _ in 0..3 {
            port.write_all(&[0x23, 0x05, 0x00])?;
            let bytes_read = port.read(serial_buf.as_mut_slice())?;
            if bytes_read >= 2 && serial_buf.starts_with(&[0x23, 0x05]) {
                break;
            }
        }
        for _ in 0..3 {
            port.write_all(&[0x23, 0x04, 0x00])?;
            let bytes_read = port.read(serial_buf.as_mut_slice())?;
            if bytes_read >= 2 && serial_buf.starts_with(&[0x23, 0x04]) {
                return Ok(port);
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("{port_name} does not appear to be a Zniffer"),
        ))
    }

    /// Pulls the next parsed `Frame` from the serial buffer, blocking to read from the UART
    /// using `io_uring` when the buffer is empty or contains an incomplete frame.
    pub fn next_frame(&mut self, parser: &mut Parser) -> std::io::Result<Vec<Frame>> {
        loop {
            // 1. Try parsing complete frames from the existing buffered data
            while self.parse_idx < self.valid_len {
                // SOF hunt: find next 0x21
                if let Some(pos) = self.buf[self.parse_idx..self.valid_len]
                    .iter()
                    .position(|&b| b == 0x21)
                {
                    self.parse_idx += pos;
                } else {
                    self.parse_idx = self.valid_len;
                    break;
                }

                // Try to parse the frame starting at parse_idx
                match parser.parse_next(&self.buf[self.parse_idx..self.valid_len]) {
                    Ok((frames, rest)) => {
                        let consumed = self.buf[self.parse_idx..self.valid_len].len() - rest.len();
                        self.parse_idx += consumed;
                        if !frames.is_empty() {
                            return Ok(frames);
                        }
                    }
                    Err(ParseError::Incomplete) => {
                        // Stop parsing, we need to read more bytes into the buffer
                        break;
                    }
                    Err(ParseError::Empty) | Err(ParseError::Invalid) => {
                        // Skip this byte and hunt for the next SOF
                        self.parse_idx += 1;
                    }
                }
            }

            // 2. We need more data. Shift any remaining incomplete frame bytes to the beginning of the buffer.
            if self.parse_idx < self.valid_len {
                let len = self.valid_len - self.parse_idx;
                self.buf.copy_within(self.parse_idx..self.valid_len, 0);
                self.frame_start = len;
            } else {
                self.frame_start = 0;
            }

            // Enforce buffer safety limits
            if self.buf.len() - self.frame_start < 256 {
                self.frame_start = 0;
            }

            // Submit a read operation to the io_uring
            let read_sqe = opcode::Read::new(
                io_uring::types::Fd(self.port.as_raw_fd()),
                self.buf.as_mut_ptr().wrapping_add(self.frame_start),
                (self.buf.len() - self.frame_start) as _,
            )
            .build()
            .user_data(0x42);

            unsafe {
                self.ring
                    .submission()
                    .push(&read_sqe)
                    .expect("submission queue is full");
            }
            self.ring.submit_and_wait(1)?;

            let mut bytes_read = 0;
            for cqe in self.ring.completion() {
                if cqe.user_data() == 0x42 {
                    let result = cqe.result();
                    if result < 0 {
                        return Err(std::io::Error::from_raw_os_error(-result));
                    }
                    bytes_read = result as usize;
                }
            }

            if bytes_read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF from serial port",
                ));
            }

            self.valid_len = self.frame_start + bytes_read;
            self.parse_idx = 0;
        }
    }
}
