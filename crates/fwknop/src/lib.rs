//! Send an fwknop Single Packet Authorization (SPA) knock in one call.
//!
//! For programs that want to open a firewall hole in process instead of
//! running the `fwknop` client. The defaults match the client: SHA-256
//! message digest, port 62201, the current user's name and no client
//! timeout. Keys and modes come in an [`fkospa::KeySet`].
//!
//! ```no_run
//! use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet};
//! use fwknop::Knock;
//!
//! let keys = KeySet::new(
//!     EncryptionKey::from_base64("bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=")?,
//!     EncryptionMode::Cbc,
//!     Some(HmacKey::from_base64("ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=", HmacType::Sha256)?),
//! );
//! Knock::new("server.example.com", "203.0.113.7,tcp/22".parse()?, keys).send()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`Knock::spa_data`] builds and encrypts the packet without sending it.
//! Sending blocks only for the host-name lookup; async callers can run it
//! on a blocking thread.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::num::NonZeroU32;

pub use fkospa;
use fkospa::{AccessMessage, DigestType, KeySet, Request, SpaData, SpaMessage};

/// The UDP port fwknopd listens on by default.
pub const DEFAULT_PORT: u16 = 62201;

/// One SPA request and what is needed to encrypt and deliver it.
#[derive(Debug, Clone)]
pub struct Knock {
    /// Host name or IP of the fwknopd server.
    pub destination: String,
    /// UDP port the server listens on.
    pub port: u16,
    /// The allow IP and access spec to request.
    pub access: AccessMessage,
    pub keys: KeySet,
    pub digest_type: DigestType,
    /// `None` uses the current user's name.
    pub username: Option<String>,
    pub client_timeout: Option<NonZeroU32>,
}

impl Knock {
    /// A knock with the client's defaults: port 62201, SHA-256 digest, the
    /// current user and no client timeout.
    pub fn new(destination: impl Into<String>, access: AccessMessage, keys: KeySet) -> Knock {
        Knock {
            destination: destination.into(),
            port: DEFAULT_PORT,
            access,
            keys,
            digest_type: DigestType::default(),
            username: None,
            client_timeout: None,
        }
    }

    /// Builds and encrypts the SPA packet's payload without sending it.
    pub fn spa_data(&self) -> Result<SpaData, Error> {
        if self.keys.encryption_key.is_empty() {
            return Err(Error::Missing("encryption key"));
        }
        let mut msg = SpaMessage::new(Request::Access {
            access: self.access,
            client_timeout: self.client_timeout,
        })
        .map_err(Error::Build)?;
        msg.digest_type = self.digest_type;
        if let Some(user) = &self.username {
            msg.username = user.clone();
        }
        msg.encrypt(&self.keys).map_err(Error::Encrypt)
    }

    /// Builds, encrypts and sends the SPA packet.
    pub fn send(&self) -> Result<(), Error> {
        let data = self.spa_data()?;
        send_spa_data(&self.destination, self.port, &data)
    }
}

/// Sends SPA data to `destination:port` as one UDP datagram, trying each
/// address the destination resolves to until one can be reached.
pub fn send_spa_data(destination: &str, port: u16, data: &SpaData) -> Result<(), Error> {
    if destination.is_empty() {
        return Err(Error::Missing("destination"));
    }
    if port == 0 {
        return Err(Error::InvalidPort(port));
    }
    let target = join_host_port(destination, port);
    let addrs: Vec<SocketAddr> = (destination, port)
        .to_socket_addrs()
        .map_err(|source| Error::Dial {
            addr: target.clone(),
            source,
        })?
        .collect();

    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no addresses found");
    for addr in addrs {
        let local: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = match UdpSocket::bind(local).and_then(|s| s.connect(addr).map(|()| s)) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        return socket
            .send(data.as_str().as_bytes())
            .map(|_| ())
            .map_err(Error::Send);
    }
    Err(Error::Dial {
        addr: target,
        source: last_err,
    })
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Why a knock could not be built or sent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("invalid port {0}")]
    InvalidPort(u16),
    #[error("build SPA message: {0}")]
    Build(#[source] fkospa::Error),
    #[error("encrypt SPA message: {0}")]
    Encrypt(#[source] fkospa::Error),
    #[error("dial {addr}: {source}")]
    Dial {
        addr: String,
        #[source]
        source: io::Error,
    },
    #[error("send SPA packet: {0}")]
    Send(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, MessageType};

    use super::*;

    fn keys() -> KeySet {
        KeySet::new(
            EncryptionKey::new("0123456789abcdef0123456789abcdef"),
            EncryptionMode::Cbc,
            Some(HmacKey::new(
                "fedcba9876543210fedcba9876543210",
                HmacType::Sha256,
            )),
        )
    }

    fn knock(destination: &str, port: u16) -> Knock {
        let mut k = Knock::new(destination, "2001:db8::1,tcp/443".parse().unwrap(), keys());
        k.port = port;
        k
    }

    #[test]
    fn spa_data_round_trip() {
        let data = knock("", 0).spa_data().unwrap();
        let msg = SpaMessage::decrypt(&data, &keys()).unwrap();
        assert_eq!(msg.request.message_text(), "2001:db8::1,tcp/443");
        assert_eq!(msg.message_type(), MessageType::Access);
    }

    #[test]
    fn options_are_applied() {
        let mut k = knock("", 0);
        k.digest_type = DigestType::Sha3_512;
        k.username = Some("svc".into());
        k.client_timeout = NonZeroU32::new(45);
        let msg = SpaMessage::decrypt(&k.spa_data().unwrap(), &keys()).unwrap();
        assert_eq!(msg.digest_type, DigestType::Sha3_512);
        assert_eq!(msg.username, "svc");
        assert_eq!(msg.message_type(), MessageType::ClientTimeoutAccess);
    }

    #[test]
    fn spa_data_requires_a_key() {
        let mut k = knock("", 0);
        k.keys.encryption_key = EncryptionKey::new(Vec::new());
        assert!(matches!(k.spa_data(), Err(Error::Missing(_))));
    }

    #[test]
    fn send_rejects_bad_port_and_destination() {
        assert!(matches!(
            knock("127.0.0.1", 0).send(),
            Err(Error::InvalidPort(0))
        ));
        assert!(matches!(knock("", 62201).send(), Err(Error::Missing(_))));
    }

    #[test]
    fn send_delivers() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let port = server.local_addr().unwrap().port();

        knock("127.0.0.1", port).send().unwrap();

        let mut buf = [0u8; 2048];
        let n = server.recv(&mut buf).unwrap();
        let msg = SpaMessage::decrypt(&SpaData::from_bytes(&buf[..n]), &keys()).unwrap();
        assert_eq!(msg.request.message_text(), "2001:db8::1,tcp/443");
    }

    #[test]
    fn send_delivers_over_ipv6() {
        let Ok(server) = UdpSocket::bind("[::1]:0") else {
            return; // no IPv6 loopback on this host
        };
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        knock("::1", port).send().unwrap();
        let mut buf = [0u8; 2048];
        assert!(server.recv(&mut buf).unwrap() > 0);
    }

    #[test]
    fn host_port_joining() {
        assert_eq!(join_host_port("example.com", 1), "example.com:1");
        assert_eq!(join_host_port("::1", 62201), "[::1]:62201");
    }
}
