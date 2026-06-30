# zurf

<p align="center">
  <img src="zurf_logo.svg" alt="zurf logo" width="300" />
</p>

`zurf` is a Z-Wave frame parser utilizing UART to communicate with a Z-Wave radio loaded with the Z-Wave Zniffer firmware. It aims to parse data into a common, higher-level format than the original ABI. Zurf is named so because it rides Z-Waves. You can also think of it as Z-Wave Unwrapped RF.

Zurf is a project for me to learn Rust. As such, you may find some amateur mistakes. I welcome feedback and a chance to improve.

## Features

Right now, `zurf` is bare-bones. It does not break frames down by command class, nor does it de-encapsulate messages outside of security. These features will come at a later date. The roadmap for this project is to create two separate binaries: one very lightweight daemon that can run on an embedded device (or Linux desktop) and a cross-platform GUI that can run on any OS and receive data from the daemon. Decryption should work.

## Licensing

`zurf` is dual-licensed under two different licenses to keep the core parsing engine reusable as a library while keeping the CLI execution tool copyleft:

- **Library target (`src/lib.rs`, `src/frame.rs`, `src/mpdu.rs`, `src/types.rs`)**: Licensed under the **GNU Lesser General Public License v3.0 or later** (`LGPL-3.0-or-later`). See [LICENSE-LGPL](LICENSE-LGPL) for details.
- **Binary target (`src/main.rs`, `src/transport.rs`)**: Licensed under the **GNU General Public License v3.0 or later** (`GPL-3.0-or-later`). See [LICENSE-GPL](LICENSE-GPL) for details.

## Quick Start

### Prerequisites

- A Linux system with a modern kernel supporting `io_uring`.
- A Z-Wave Zniffer board.

### Running

To run the CLI tool, specify the serial port and the target RF region:

```bash
cargo run -p zurf-cli -- --port /dev/ttyUSB0 --region uslr  --home-id <home id in hex> --unauthenticated-key <key in hex> --mesh-authenticated-key <key in hex> --mesh-access-control-key <key in hex> --lr-authenticated-key <key in hex> --lr-access-control-key <key in hex>


```
