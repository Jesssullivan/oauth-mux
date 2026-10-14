//! Private current-writer verified native transports. R-N13.
//! The C bridge is an exact copy of Omux's reviewed peer implementation.

use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

pub const MAX_PACKET: usize = 65_536;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn random_handle() -> io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let mut bytes = [0u8; 32];
        let mut count = 0;
        while count < bytes.len() {
            // Safety: kernel fills only the remaining initialized array extent.
            let received = unsafe {
                libc::getrandom(bytes[count..].as_mut_ptr().cast(), bytes.len() - count, 0)
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if received == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "native entropy unavailable",
                ));
            }
            count += received as usize;
        }
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native owner peer profile unavailable",
        ))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Namespace {
    device: u64,
    inode: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Witness {
    profile: u32,
    boot_id: [u8; 16],
    pidfs_device: u64,
    pidfs_inode: u64,
    user_namespace: Namespace,
    pid_namespace: Namespace,
    uid: u32,
    gid: u32,
}
/// Typed original OS attribution. It has no public constructor, raw FD or
/// serialization and cannot be supplied through JSON as authentication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerWitness(Witness);
#[repr(C)]
struct Context {
    socket_fd: i32,
    pidfd: i32,
    owns_socket: i32,
    witness: Witness,
}
unsafe extern "C" {
    fn omux_peer_enable(fd: i32) -> i32;
    fn omux_peer_capture(fd: i32, uid: u32, out: *mut Context) -> i32;
    fn omux_peer_receive(
        peer: *mut Context,
        buffer: *mut u8,
        capacity: usize,
        packet: i32,
        count: *mut usize,
    ) -> i32;
    fn omux_peer_close(peer: *mut Context);
}

fn status(code: i32) -> io::Result<()> {
    let kind = match code {
        0 => return Ok(()),
        1 => io::ErrorKind::Unsupported,
        2 | 4 | 5 | 6 | 9 => io::ErrorKind::PermissionDenied,
        7 | 13 => io::ErrorKind::ConnectionAborted,
        10 => io::ErrorKind::WouldBlock,
        11 => io::ErrorKind::Interrupted,
        3 | 8 => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    Err(io::Error::new(
        kind,
        "native peer profile or current writer refused",
    ))
}

#[cfg(unix)]
struct Connection {
    peer: Context,
    socket: OwnedFd,
    deadline: Instant,
    packet: bool,
}
#[cfg(unix)]
impl Drop for Connection {
    fn drop(&mut self) {
        // Safety: this context owns its pidfd and borrows the still-live socket.
        unsafe { omux_peer_close(&mut self.peer) };
    }
}

#[cfg(unix)]
fn socket_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    // Safety: sockaddr_un is a plain C value, initialized before use.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() >= address.sun_path.len()
        || bytes.contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native endpoint path refused",
        ));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as _;
    }
    Ok((
        address,
        std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
    ))
}

#[cfg(target_os = "linux")]
fn new_socket(packet: bool) -> io::Result<OwnedFd> {
    // Safety: creates an owned nonblocking descriptor with no borrowed memory.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            (if packet {
                libc::SOCK_SEQPACKET
            } else {
                libc::SOCK_STREAM
            }) | libc::SOCK_CLOEXEC
                | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: socket returned a fresh descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // Enable before connect/listen so the first byte cannot bypass verification.
    // Safety: fd is an open socket; bridge does not retain memory pointers.
    status(unsafe { omux_peer_enable(fd) })?;
    Ok(socket)
}
#[cfg(all(unix, not(target_os = "linux")))]
fn new_socket(_packet: bool) -> io::Result<OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native owner peer profile unavailable",
    ))
}

#[cfg(unix)]
fn wait(fd: i32, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "native exchange timed out"))?;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = remaining.as_millis().clamp(1, 10_000) as i32;
        // Safety: one valid pollfd for the duration of this bounded call.
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native exchange timed out",
            ));
        }
        if poll.revents & events != 0 {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "native peer disconnected",
        ));
    }
}

#[cfg(unix)]
impl Connection {
    fn capture(socket: OwnedFd, packet: bool, deadline: Instant) -> io::Result<Self> {
        let mut peer = Context {
            socket_fd: -1,
            pidfd: -1,
            owns_socket: 0,
            witness: Witness::default(),
        };
        // Safety: fresh context output; getuid reads local credentials only.
        status(unsafe { omux_peer_capture(socket.as_raw_fd(), libc::getuid(), &mut peer) })?;
        Ok(Self {
            peer,
            socket,
            deadline,
            packet,
        })
    }
    fn connect(path: &Path, packet: bool) -> io::Result<Self> {
        let socket = new_socket(packet)?;
        let (address, length) = socket_address(path)?;
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        // Safety: address points to initialized sockaddr_un for this call.
        if unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS)
                && error.kind() != io::ErrorKind::WouldBlock
            {
                return Err(error);
            }
            wait(socket.as_raw_fd(), libc::POLLOUT, deadline)?;
            let mut code = 0i32;
            let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
            // Safety: correctly sized SO_ERROR output pointers.
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut code as *mut i32).cast(),
                    &mut size,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if size != std::mem::size_of::<i32>() as libc::socklen_t {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native connect evidence refused",
                ));
            }
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code));
            }
        }
        Self::capture(socket, packet, deadline)
    }
    fn receive(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() || bytes.len() > MAX_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native receive size refused",
            ));
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native exchange timed out",
                ));
            }
            let mut count = 0;
            // Safety: bridge borrows initialized context and writable bounded buffer.
            match status(unsafe {
                omux_peer_receive(
                    &mut self.peer,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    i32::from(self.packet),
                    &mut count,
                )
            }) {
                Ok(()) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.socket.as_raw_fd(), libc::POLLIN, self.deadline)?
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || (self.packet && bytes.len() > MAX_PACKET) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native send size refused",
            ));
        }
        let mut sent = 0;
        while sent < bytes.len() {
            wait(self.socket.as_raw_fd(), libc::POLLOUT, self.deadline)?;
            // Safety: initialized borrowed bytes and live socket; no SIGPIPE delivery.
            let count = unsafe {
                libc::send(
                    self.socket.as_raw_fd(),
                    bytes[sent..].as_ptr().cast(),
                    bytes.len() - sent,
                    libc::MSG_NOSIGNAL,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(error);
            }
            if count == 0 || (self.packet && count as usize != bytes.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "native packet send incomplete",
                ));
            }
            sent += count as usize;
        }
        Ok(())
    }
}

pub struct VerifiedStream {
    #[cfg(unix)]
    connection: Connection,
    #[cfg(not(unix))]
    unavailable: (),
}
impl VerifiedStream {
    pub fn witness(&self) -> PeerWitness {
        #[cfg(unix)]
        {
            PeerWitness(self.connection.peer.witness)
        }
        #[cfg(not(unix))]
        {
            unreachable!("unsupported platforms cannot construct verified streams")
        }
    }
    pub fn connect(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                connection: Connection::connect(path, false)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
    pub fn send_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.connection.send(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
    pub fn recv_segment(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.connection.receive(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
}

pub struct VerifiedPacket {
    #[cfg(unix)]
    connection: Connection,
    #[cfg(not(unix))]
    unavailable: (),
}
impl VerifiedPacket {
    /// Original exchange cutoff; callers must not restart this clock.
    pub fn deadline(&self) -> Instant {
        #[cfg(unix)]
        { self.connection.deadline }
        #[cfg(not(unix))]
        { unreachable!("unsupported platforms cannot construct verified packets") }
    }
    pub fn witness(&self) -> PeerWitness {
        #[cfg(unix)]
        {
            PeerWitness(self.connection.peer.witness)
        }
        #[cfg(not(unix))]
        {
            unreachable!("unsupported platforms cannot construct verified packets")
        }
    }
    pub fn connect(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                connection: Connection::connect(path, true)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
    pub fn send_packet(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.connection.send(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
    pub fn recv_packet(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.connection.receive(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
}

pub struct PacketListener {
    #[cfg(unix)]
    socket: OwnedFd,
    #[cfg(not(unix))]
    unavailable: (),
}
impl PacketListener {
    /// Caller owns the private directory and lifecycle of the exact fresh path.
    pub fn bind(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let socket = new_socket(true)?;
            let (address, length) = socket_address(path)?;
            // Safety: initialized sockaddr; socket is owned and unbound.
            if unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    length,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            // Safety: live bound socket; fixed bounded backlog.
            if unsafe { libc::listen(socket.as_raw_fd(), 16) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { socket })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
    pub fn try_accept(&self) -> io::Result<VerifiedPacket> {
        #[cfg(target_os = "linux")]
        {
            // Safety: accepts without writing peer address; flags prevent blocking/leak.
            let fd = unsafe {
                libc::accept4(
                    self.socket.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // Safety: successful accept returns a fresh owned descriptor.
            let socket = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(VerifiedPacket {
                connection: Connection::capture(socket, true, Instant::now() + EXCHANGE_TIMEOUT)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native peer profile unavailable",
            ))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn packet_bridge_verifies_both_directions_and_rejects_truncation() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("owner.sock");
        let listener = PacketListener::bind(&path)?;
        let mut client = VerifiedPacket::connect(&path)?;
        let mut server = listener.try_accept()?;
        client.send_packet(b"identify")?;
        let mut bytes = [0u8; 64];
        let count = server.recv_packet(&mut bytes)?;
        assert_eq!(&bytes[..count], b"identify");
        server.send_packet(b"identity")?;
        let count = client.recv_packet(&mut bytes)?;
        assert_eq!(&bytes[..count], b"identity");
        // A permitted packet that exceeds this receiver's capacity must never
        // expose a truncated JSON prefix as an authenticated operation.
        client.send_packet(&[b'x'; 128])?;
        assert_eq!(
            server.recv_packet(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(bytes.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn stream_bridge_verifies_each_segment_and_keeps_absolute_deadline() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("adapter.sock");
        let listener = new_socket(false)?;
        let (address, length) = socket_address(&path)?;
        // Safety: test owns descriptor/address and starts a bounded local listener.
        if unsafe {
            libc::bind(
                listener.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // Safety: live bound socket and fixed backlog.
        if unsafe { libc::listen(listener.as_raw_fd(), 1) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut client = VerifiedStream::connect(&path)?;
        // Safety: local queued connection, no address output, owned result.
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Safety: fresh accepted descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut server = VerifiedStream {
            connection: Connection::capture(socket, false, Instant::now() + EXCHANGE_TIMEOUT)?,
        };
        client.send_all(b"ab")?;
        let mut bytes = [0u8; 1];
        assert_eq!(server.recv_segment(&mut bytes)?, 1);
        assert_eq!(&bytes, b"a");
        assert_eq!(server.recv_segment(&mut bytes)?, 1);
        assert_eq!(&bytes, b"b");
        server.send_all(b"reply\n")?;
        let mut response = [0u8; 64];
        let count = client.recv_segment(&mut response)?;
        assert_eq!(&response[..count], b"reply\n");
        server.connection.deadline = Instant::now();
        assert_eq!(
            server.recv_segment(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        Ok(())
    }
}
