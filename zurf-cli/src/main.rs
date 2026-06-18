// SPDX-License-Identifier: GPL-3.0-or-later

mod transport;
mod zniffer;
use zurf::{
    keys::{self, KeyStore},
    security::Key,
    types::HomeId,
};

struct Args {
    port: String,
    region: u8,
    home: Option<HomeId>,
    unauthenticated_key: Option<Key>,
    mesh_authenticated_key: Option<Key>,
    mesh_access_control_key: Option<Key>,
    lr_authenticated_key: Option<Key>,
    lr_access_control_key: Option<Key>,
}

fn parse_region(s: &str) -> Option<u8> {
    match s.to_lowercase().as_str() {
        "anz" | "australia" | "nz" => Some(0x02),
        "hk" | "hongkong" => Some(0x03),
        "in" | "india" => Some(0x05),
        "il" | "israel" => Some(0x06),
        "ru" | "russia" => Some(0x07),
        "cn" | "china" => Some(0x08),
        "us" | "uslr" => Some(0x09),
        "eu" | "eulr" => Some(0x0b),
        "jp" | "japan" => Some(0x20),
        "kr" | "korea" => Some(0x21),
        _ => s.parse::<u8>().ok(),
    }
}

pub fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != (2 * N) {
        return Err(format!(
            "Hex string must be exactly {} characters long",
            (2 * N)
        ));
    }
    let mut bytes = [0u8; N];
    for i in 0..N {
        bytes[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|e| format!("Invalid hex: {}", e))?;
    }
    Ok(bytes)
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut port = None;
    let mut region = None;
    let mut home: Option<HomeId> = None;
    //let mut s0_key: Option<Key> = None;
    let mut unauthenticated_key: Option<Key> = None;
    let mut mesh_authenticated_key: Option<Key> = None;
    let mut mesh_access_control_key: Option<Key> = None;
    let mut lr_authenticated_key: Option<Key> = None;
    let mut lr_access_control_key: Option<Key> = None;
    const HELP: &str = "Usage: zurf --port <port> --region <region> [--s0-key <key> --unauthenticated-key <key> --mesh-authenticated-key <key> --mesh-access-control-key <key> --lr-authenticated-key <key> --lr-access-control-key <key>]\n\n\
                     Supported regions:\n  \
                     eu, us, anz, hk, in, il, ru, cn, uslr, eulr, jp, kr\n  \
                     (or pass a raw decimal/hex value)";
    if args.len() == 0 {
        return Err(HELP.to_string());
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-p" | "--port" => {
                port = Some(args.next().ok_or("Missing value for --port")?);
            }
            "-r" | "--region" => {
                let r_str = args.next().ok_or("Missing value for --region")?;
                let r_val =
                    parse_region(&r_str).ok_or_else(|| format!("Invalid region '{}'", r_str))?;
                region = Some(r_val);
            }
            "--home" | "--home-id" => {
                let k_str = args.next().ok_or("Missing value for --home")?;
                let k_val = decode_hex(&k_str)?;
                home = Some(HomeId(u32::from_be_bytes(k_val)));
            }
            //"--s0-key" => {
            //    let k_str = args.next().ok_or("Missing value for --s0-key")?;
            //    let k_val = decode_hex(&k_str)?;
            //    s0_key = Some(Key::new(k_val));
            //}
            "--unauthenticated-key" => {
                let k_str = args
                    .next()
                    .ok_or("Missing value for --unauthenticated-key")?;
                let k_val = decode_hex(&k_str)?;
                unauthenticated_key = Some(Key::new(k_val));
            }
            "--mesh-authenticated-key" => {
                let k_str = args
                    .next()
                    .ok_or("Missing value for --mesh-authenticated-key")?;
                let k_val = decode_hex(&k_str)?;
                mesh_authenticated_key = Some(Key::new(k_val));
            }
            "--mesh-access-control-key" => {
                let k_str = args
                    .next()
                    .ok_or("Missing value for --mesh-access-control-key")?;
                let k_val = decode_hex(&k_str)?;
                mesh_access_control_key = Some(Key::new(k_val));
            }
            "--lr-authenticated-key" => {
                let k_str = args
                    .next()
                    .ok_or("Missing value for --lr-authenticated-key")?;
                let k_val = decode_hex(&k_str)?;
                lr_authenticated_key = Some(Key::new(k_val));
            }
            "--lr-access-control-key" => {
                let k_str = args
                    .next()
                    .ok_or("Missing value for --lr-access-control-key")?;
                let k_val = decode_hex(&k_str)?;
                lr_access_control_key = Some(Key::new(k_val));
            }
            _ => {
                return Err(HELP.to_string());
            }
        }
    }

    let port =
        port.ok_or("Missing required argument --port. Use --help for usage instructions.")?;
    let region =
        region.ok_or("Missing required argument --region. Use --help for usage instructions.")?;
    Ok(Args {
        port,
        region,
        home,
        unauthenticated_key,
        mesh_authenticated_key,
        mesh_access_control_key,
        lr_authenticated_key,
        lr_access_control_key,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    println!(
        "Opening Zniffer on port {} (region: {:#04X})...",
        args.port, args.region
    );
    let keyring = keys::KeyRing::new(
        args.unauthenticated_key,
        args.mesh_authenticated_key,
        args.mesh_access_control_key,
        args.lr_authenticated_key,
        args.lr_access_control_key,
    );
    let transport = transport::IoUringUART::new(&args.port, args.region)?;

    let mut keystore = keys::LruKeyStore::default();
    if let Some(home) = args.home {
        keystore.insert_keyring(home, keyring);
    }
    let parser = zurf::parser::Parser::new(keystore);
    let mut zniffer = zniffer::Zniffer::new(parser, transport);

    println!("Zniffer initialized successfully. Sniffing...");
    loop {
        match zniffer.next_frame() {
            Ok(frames) => {
                for frame in frames {
                    println!("Parsed frame: {:#02X?}", frame);
                }
            }
            Err(e) => {
                eprintln!("I/O Error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
