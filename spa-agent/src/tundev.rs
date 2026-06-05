//! The TUN device, presented to smoltcp as a `phy::Device`. We bridge the TUN
//! through channels to a reader and a writer thread, so the single-threaded
//! smoltcp poll loop never blocks on the device and we need no `unsafe`/raw-fd
//! handling. The device speaks raw IP packets (`Medium::Ip`).

use std::error::Error;
use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use tun::Device as _; // brings the `name()` trait method into scope

const MTU: usize = 1500;

/// Create a TUN configured with `address`/`netmask` (so the mesh CIDR is on-link
/// and routes into it) and return a smoltcp device plus the interface name.
pub fn open(address: std::net::Ipv4Addr, prefix: u8) -> Result<(TunPhy, String), Box<dyn Error>> {
    let mut config = tun::Configuration::default();
    config
        .address(address)
        .netmask(prefix_to_mask(prefix))
        .mtu(MTU as i32)
        .up();
    // No packet-info header — smoltcp wants raw IP frames.
    config.platform(|p| {
        p.packet_information(false);
    });
    let dev = tun::create(&config)?;
    let name = dev.name()?;

    // Independent read/write halves, each driven by its own thread to/from a
    // channel, so the single-threaded smoltcp loop never blocks on the device.
    let (mut reader, mut writer) = dev.split();

    let (rx_tx, rx_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; MTU];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if rx_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    let (tx_tx, tx_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(pkt) = tx_rx.recv() {
            if writer.write_all(&pkt).is_err() {
                break;
            }
        }
    });

    Ok((
        TunPhy {
            rx: rx_rx,
            tx: tx_tx,
        },
        name,
    ))
}

fn prefix_to_mask(prefix: u8) -> std::net::Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    std::net::Ipv4Addr::from(bits)
}

pub struct TunPhy {
    rx: Receiver<Vec<u8>>,
    tx: Sender<Vec<u8>>,
}

impl Device for TunPhy {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.rx.try_recv() {
            Ok(buf) => Some((RxToken { buf }, TxToken { tx: &self.tx })),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { tx: &self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        // The host stack offloads transport checksums on a TUN, so inbound packets
        // can carry blank ones — don't verify on rx; still compute on tx so our
        // replies are valid on the wire.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps
    }
}

pub struct RxToken {
    buf: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

pub struct TxToken<'a> {
    tx: &'a Sender<Vec<u8>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        let _ = self.tx.send(buf);
        result
    }
}
