// SPDX-License-Identifier: GPL-3.0-or-later

mod transport;

struct Args {
    port: String,
    region: u8,
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

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut port = None;
    let mut region = None;

    if args.len() == 0 {
        return Err("Usage: zurf --port <port> [--region <region>]\n\n\
                     Supported regions:\n  \
                     eu, us, anz, hk, in, il, ru, cn, uslr, eulr, jp, kr\n  \
                     (or pass a raw decimal/hex value)"
            .to_string());
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
            _ => {
                return Err("Usage: zurf --port <port> [--region <region>]\n\n\
                     Supported regions:\n  \
                     eu, us, anz, hk, in, il, ru, cn, uslr, eulr, jp, kr\n  \
                     (or pass a raw decimal/hex value)"
                    .to_string());
            }
        }
    }

    let port =
        port.ok_or("Missing required argument --port. Use --help for usage instructions.")?;
    let region =
        region.ok_or("Missing required argument --region. Use --help for usage instructions.")?;
    Ok(Args { port, region })
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
    let mut transport = transport::ZnifferTransport::new(&args.port, args.region)?;
    println!("Zniffer initialized successfully. Sniffing...");

    loop {
        match transport.next_frame() {
            Ok(frame) => {
                println!("Parsed frame: {:#02X?}", frame);
            }
            Err(e) => {
                eprintln!("I/O Error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
