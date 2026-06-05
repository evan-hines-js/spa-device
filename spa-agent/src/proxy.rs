//! The datapath: a userspace TCP terminator over the TUN (smoltcp). For each
//! known mesh endpoint `(mesh_ip, port)` we keep a listening socket; when a
//! workstation app connects (e.g. `ssh demo-svc`), we knock that endpoint's gate,
//! dial the real backend `address:port` through the pinhole, and splice bytes
//! both ways. Conntrack on the gate holds the established flow open.

use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use spa_client::Knocker;

use crate::tundev::TunPhy;

/// Everything needed to reach one endpoint's gate + backend.
pub struct Target {
    pub backend: SocketAddr,
    pub knocker: Knocker,
    pub knock_target: String,
    pub knock_ports: Vec<u16>,
}

const BUF: usize = 65535;
const POLL_SLEEP: Duration = Duration::from_millis(2);
const KNOCK_GRACE: Duration = Duration::from_millis(40);

struct Flow {
    handle: SocketHandle,
    backend: TcpStream,
    to_backend: Vec<u8>,
    to_mesh: Vec<u8>,
}

fn now() -> Instant {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Instant::from_micros(d.as_micros() as i64)
}

fn listener(set: &mut SocketSet, ip: Ipv4Addr, port: u16) -> Result<SocketHandle, Box<dyn Error>> {
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUF]),
        tcp::SocketBuffer::new(vec![0; BUF]),
    );
    sock.listen((IpAddress::Ipv4(ip), port))?;
    Ok(set.add(sock))
}

/// Run the datapath forever. `agent_ip`/`prefix` is the TUN's own address on the
/// mesh CIDR; `targets` is keyed by the `(mesh_ip, port)` each listener serves.
pub fn run(
    mut device: TunPhy,
    agent_ip: Ipv4Addr,
    prefix: u8,
    targets: HashMap<(Ipv4Addr, u16), Target>,
) -> Result<(), Box<dyn Error>> {
    let mut iface = Interface::new(
        Config::new(smoltcp::wire::HardwareAddress::Ip),
        &mut device,
        now(),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(agent_ip), prefix));
    });
    iface.set_any_ip(true);
    // any_ip accepts a non-local destination only when a route resolves it to one
    // of *our own* addresses (smoltcp checks `has_ip_addr(router_addr)`), so the
    // default route's gateway must be the interface's own IP.
    iface.routes_mut().add_default_ipv4_route(agent_ip)?;

    let mut sockets = SocketSet::new(Vec::new());
    // One listening socket per endpoint; `listening[key]` is the handle currently
    // in Listen state, replaced when a connection lands on it.
    let mut listening: HashMap<(Ipv4Addr, u16), SocketHandle> = HashMap::new();
    for &(ip, port) in targets.keys() {
        listening.insert((ip, port), listener(&mut sockets, ip, port)?);
    }
    let mut flows: Vec<Flow> = Vec::new();

    loop {
        iface.poll(now(), &mut device, &mut sockets);

        // A listener that left Listen state has accepted a connection: promote it
        // to a flow (knock + dial backend) and open a fresh listener in its place.
        let keys: Vec<(Ipv4Addr, u16)> = listening.keys().copied().collect();
        for key in keys {
            let handle = listening[&key];
            let sock = sockets.get::<tcp::Socket>(handle);
            if sock.state() != tcp::State::Listen && sock.is_active() {
                listening.insert(key, listener(&mut sockets, key.0, key.1)?);
                if let Some(target) = targets.get(&key) {
                    match dial(target) {
                        Ok(backend) => {
                            println!(
                                "open {}:{} -> {} (knocked {})",
                                key.0, key.1, target.backend, target.knock_target
                            );
                            flows.push(Flow {
                                handle,
                                backend,
                                to_backend: Vec::new(),
                                to_mesh: Vec::new(),
                            });
                        }
                        Err(e) => {
                            eprintln!("{}: {e}", target.backend);
                            sockets.get_mut::<tcp::Socket>(handle).abort();
                        }
                    }
                }
            }
        }

        flows.retain_mut(|flow| pump(&mut sockets, flow));

        std::thread::sleep(POLL_SLEEP);
    }
}

/// Knock the endpoint's gate, then connect to the real backend through the
/// pinhole (re-knock once on a transient miss — the SYN can beat the grant).
fn dial(target: &Target) -> Result<TcpStream, Box<dyn Error>> {
    let mut last = String::new();
    for _ in 0..3 {
        target
            .knocker
            .knock(&target.knock_target, &target.knock_ports)?;
        std::thread::sleep(KNOCK_GRACE);
        match TcpStream::connect_timeout(&target.backend, Duration::from_secs(2)) {
            Ok(s) => {
                s.set_nonblocking(true)?;
                return Ok(s);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("backend unreachable after knocking: {last}").into())
}

/// Move bytes both ways for one flow. Returns false when the flow is finished and
/// should be dropped.
fn pump(sockets: &mut SocketSet, flow: &mut Flow) -> bool {
    let sock = sockets.get_mut::<tcp::Socket>(flow.handle);

    // mesh -> backend
    if flow.to_backend.is_empty() && sock.can_recv() {
        let _ = sock.recv(|data| {
            flow.to_backend.extend_from_slice(data);
            (data.len(), ())
        });
    }
    if !flow.to_backend.is_empty() {
        match flow.backend.write(&flow.to_backend) {
            Ok(n) => drop(flow.to_backend.drain(..n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }

    // backend -> mesh
    if flow.to_mesh.is_empty() {
        let mut buf = [0u8; BUF];
        match flow.backend.read(&mut buf) {
            Ok(0) => {
                sock.close();
                return sock.is_open();
            }
            Ok(n) => flow.to_mesh.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
    if !flow.to_mesh.is_empty() && sock.can_send() {
        if let Ok(n) = sock.send_slice(&flow.to_mesh) {
            drop(flow.to_mesh.drain(..n));
        }
    }

    // Drop once the mesh side is fully closed and nothing is buffered.
    sock.is_open() || !flow.to_mesh.is_empty() || !flow.to_backend.is_empty()
}
