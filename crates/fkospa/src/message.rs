//! SPA messages: what they contain, and how they are encoded, encrypted,
//! decrypted and decoded.

use std::fmt;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;

use crate::algorithms::{DigestType, HmacType};
use crate::b64;
use crate::cipher;
use crate::error::{Error, invalid, missing};
use crate::keys::KeySet;
use crate::spa_data::SpaData;

/// The SPA protocol version this crate speaks. It must match what C fwknopd
/// expects.
pub const PROTOCOL_VERSION: &str = "3.0.0";

/// Base64 of `"Salted__"`: every AES ciphertext starts with it, so it is
/// left off the wire and restored before decryption.
const B64_SALT_PREFIX: &str = "U2FsdGVkX1";

const MIN_ENCODED_LEN: usize = 36;
const MAX_ENCODED_LEN: usize = 1500;
const MAX_USERNAME_LEN: usize = 64;
const MAX_COMMAND_LEN: usize = 1400;
const MAX_NAT_ACCESS_LEN: usize = 128;
const MAX_ACCESS_MESSAGE_LEN: usize = 256;
const RAND_VAL_LEN: usize = 16;
const MIN_FIELDS: usize = 6;
const MAX_FIELDS: usize = 9;

/// The random value at the start of every SPA message: exactly 16 decimal
/// digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RandVal(String);

impl RandVal {
    /// 16 random decimal digits.
    pub fn random() -> Result<RandVal, Error> {
        let mut digits = String::with_capacity(RAND_VAL_LEN);
        while digits.len() < RAND_VAL_LEN {
            let mut byte = [0u8; 1];
            getrandom::fill(&mut byte).map_err(|e| Error::Random(e.to_string()))?;
            // Reject 250..=255 so every digit is equally likely.
            if byte[0] < 250 {
                digits.push(char::from(b'0' + byte[0] % 10));
            }
        }
        Ok(RandVal(digits))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RandVal {
    type Err = Error;

    fn from_str(s: &str) -> Result<RandVal, Error> {
        if s.len() != RAND_VAL_LEN {
            return Err(invalid(format!(
                "rand_val must be {RAND_VAL_LEN} chars, got {}",
                s.len()
            )));
        }
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return Err(invalid("rand_val must be numeric"));
        }
        Ok(RandVal(s.to_string()))
    }
}

impl fmt::Display for RandVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The protocol in an access spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
        })
    }
}

/// Parses exactly `tcp`, `udp` or `icmp` (lower case, as fwknop does).
impl FromStr for Proto {
    type Err = Error;

    fn from_str(s: &str) -> Result<Proto, Error> {
        match s {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "icmp" => Ok(Proto::Icmp),
            _ => Err(invalid(format!("invalid proto: {s}"))),
        }
    }
}

/// A protocol and port the client wants opened, written `proto/port`
/// (for example `tcp/22`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessSpec {
    pub proto: Proto,
    pub port: NonZeroU16,
}

impl AccessSpec {
    pub fn new(proto: Proto, port: NonZeroU16) -> AccessSpec {
        AccessSpec { proto, port }
    }

    /// Parses `proto/port`. With `canonical`, a port with leading zeros is
    /// rejected (as fwknop-go's server does) instead of normalised.
    fn parse(s: &str, canonical: bool) -> Result<AccessSpec, Error> {
        let bad = || invalid(format!("invalid proto/port: {s}"));
        let (proto, port) = s.split_once('/').ok_or_else(bad)?;
        let proto: Proto = proto.parse().map_err(|_| bad())?;
        if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        if canonical && port.starts_with('0') {
            return Err(invalid(format!("invalid port: {port}")));
        }
        let port: u32 = port
            .parse()
            .map_err(|_| invalid(format!("port out of range: {port}")))?;
        let port = u16::try_from(port)
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| invalid(format!("port out of range: {port}")))?;
        Ok(AccessSpec { proto, port })
    }
}

impl fmt::Display for AccessSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.proto, self.port)
    }
}

/// Parses `tcp/22`. Leading zeros in the port are accepted and dropped.
impl FromStr for AccessSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<AccessSpec, Error> {
        AccessSpec::parse(s, false)
    }
}

/// An allow IP paired with an access spec, written `allow_ip,proto/port`
/// (for example `203.0.113.7,tcp/22`).
///
/// An allow IP of `0.0.0.0` or `::` asks the server to open access for the
/// packet source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessMessage {
    pub allow_ip: IpAddr,
    pub spec: AccessSpec,
}

impl AccessMessage {
    pub fn new(allow_ip: IpAddr, spec: AccessSpec) -> AccessMessage {
        AccessMessage { allow_ip, spec }
    }

    fn parse(s: &str, canonical: bool) -> Result<AccessMessage, Error> {
        if s.is_empty() {
            return Err(missing("access message is empty"));
        }
        if s.len() > MAX_ACCESS_MESSAGE_LEN {
            return Err(invalid("access message too long"));
        }
        let (ip, spec) = s
            .split_once(',')
            .ok_or_else(|| invalid("access message must be IP,proto/port"))?;
        let allow_ip: IpAddr = ip
            .parse()
            .map_err(|_| invalid(format!("invalid IP in access message: {ip}")))?;
        Ok(AccessMessage {
            allow_ip,
            spec: AccessSpec::parse(spec, canonical)?,
        })
    }
}

impl fmt::Display for AccessMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.allow_ip, self.spec)
    }
}

/// Parses `allow_ip,proto/port`.
impl FromStr for AccessMessage {
    type Err = Error;

    fn from_str(s: &str) -> Result<AccessMessage, Error> {
        AccessMessage::parse(s, false)
    }
}

/// Which of the seven kinds an SPA message is. On the wire it is a number
/// from 0 to 6; here it is derived from the [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Command,
    Access,
    NatAccess,
    ClientTimeoutAccess,
    ClientTimeoutNatAccess,
    LocalNatAccess,
    ClientTimeoutLocalNatAccess,
}

impl MessageType {
    /// The number used on the wire.
    pub fn code(self) -> u8 {
        match self {
            MessageType::Command => 0,
            MessageType::Access => 1,
            MessageType::NatAccess => 2,
            MessageType::ClientTimeoutAccess => 3,
            MessageType::ClientTimeoutNatAccess => 4,
            MessageType::LocalNatAccess => 5,
            MessageType::ClientTimeoutLocalNatAccess => 6,
        }
    }

    fn from_code(code: i64) -> Option<MessageType> {
        Some(match code {
            0 => MessageType::Command,
            1 => MessageType::Access,
            2 => MessageType::NatAccess,
            3 => MessageType::ClientTimeoutAccess,
            4 => MessageType::ClientTimeoutNatAccess,
            5 => MessageType::LocalNatAccess,
            6 => MessageType::ClientTimeoutLocalNatAccess,
            _ => return None,
        })
    }

    fn requires_nat_access(self) -> bool {
        matches!(
            self,
            MessageType::NatAccess
                | MessageType::ClientTimeoutNatAccess
                | MessageType::LocalNatAccess
                | MessageType::ClientTimeoutLocalNatAccess
        )
    }

    fn requires_client_timeout(self) -> bool {
        matches!(
            self,
            MessageType::ClientTimeoutAccess
                | MessageType::ClientTimeoutNatAccess
                | MessageType::ClientTimeoutLocalNatAccess
        )
    }
}

/// Formats like fwknop-go: `Command`, `Access`, `NATAccess`,
/// `ClientTimeoutAccess`, …
impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MessageType::Command => "Command",
            MessageType::Access => "Access",
            MessageType::NatAccess => "NATAccess",
            MessageType::ClientTimeoutAccess => "ClientTimeoutAccess",
            MessageType::ClientTimeoutNatAccess => "ClientTimeoutNATAccess",
            MessageType::LocalNatAccess => "LocalNATAccess",
            MessageType::ClientTimeoutLocalNatAccess => "ClientTimeoutLocalNATAccess",
        })
    }
}

/// What an SPA message asks the server to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Run a server command (message type 0).
    Command(String),
    /// Open access for an access message (message type 1, or 3 with a
    /// client timeout).
    Access {
        access: AccessMessage,
        client_timeout: Option<NonZeroU32>,
    },
    /// Open access and forward through NAT (message type 2, or 4).
    NatAccess {
        access: AccessMessage,
        nat_access: String,
        client_timeout: Option<NonZeroU32>,
    },
    /// Open access with local NAT (message type 5, or 6).
    LocalNatAccess {
        access: AccessMessage,
        nat_access: String,
        client_timeout: Option<NonZeroU32>,
    },
}

impl Request {
    /// An access request with no client timeout.
    pub fn access(access: AccessMessage) -> Request {
        Request::Access {
            access,
            client_timeout: None,
        }
    }

    /// The message type this request is sent as.
    pub fn message_type(&self) -> MessageType {
        let timeout = self.client_timeout().is_some();
        match (self, timeout) {
            (Request::Command(_), _) => MessageType::Command,
            (Request::Access { .. }, false) => MessageType::Access,
            (Request::Access { .. }, true) => MessageType::ClientTimeoutAccess,
            (Request::NatAccess { .. }, false) => MessageType::NatAccess,
            (Request::NatAccess { .. }, true) => MessageType::ClientTimeoutNatAccess,
            (Request::LocalNatAccess { .. }, false) => MessageType::LocalNatAccess,
            (Request::LocalNatAccess { .. }, true) => MessageType::ClientTimeoutLocalNatAccess,
        }
    }

    /// The access message, unless this is a server command.
    pub fn access_message(&self) -> Option<&AccessMessage> {
        match self {
            Request::Command(_) => None,
            Request::Access { access, .. }
            | Request::NatAccess { access, .. }
            | Request::LocalNatAccess { access, .. } => Some(access),
        }
    }

    /// The NAT access string, for NAT requests.
    pub fn nat_access(&self) -> Option<&str> {
        match self {
            Request::NatAccess { nat_access, .. } | Request::LocalNatAccess { nat_access, .. } => {
                Some(nat_access)
            }
            _ => None,
        }
    }

    /// The client timeout, if the client asked for one.
    pub fn client_timeout(&self) -> Option<NonZeroU32> {
        match self {
            Request::Command(_) => None,
            Request::Access { client_timeout, .. }
            | Request::NatAccess { client_timeout, .. }
            | Request::LocalNatAccess { client_timeout, .. } => *client_timeout,
        }
    }

    /// The text carried in the message field: the access message, or the
    /// server command.
    pub fn message_text(&self) -> String {
        match self {
            Request::Command(cmd) => cmd.clone(),
            other => other
                .access_message()
                .map(ToString::to_string)
                .unwrap_or_default(),
        }
    }
}

/// The decrypted, decoded contents of SPA data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaMessage {
    pub rand_val: RandVal,
    pub username: String,
    /// Unix seconds.
    pub timestamp: i64,
    pub request: Request,
    pub server_auth: Option<String>,
    pub digest_type: DigestType,
}

impl SpaMessage {
    /// A message for `request` with fwknop's defaults: a random value, the
    /// current user's name, the current time and a SHA-256 message digest.
    pub fn new(request: Request) -> Result<SpaMessage, Error> {
        Ok(SpaMessage {
            rand_val: RandVal::random()?,
            username: crate::user::current_username()?,
            timestamp: unix_now(),
            request,
            server_auth: None,
            digest_type: DigestType::default(),
        })
    }

    /// The message type this message is sent as.
    pub fn message_type(&self) -> MessageType {
        self.request.message_type()
    }

    /// The plaintext that gets encrypted: the colon-separated fields followed
    /// by `:` and the message digest.
    ///
    /// ```text
    /// RAND_VAL:B64(USER):TIMESTAMP:3.0.0:TYPE:B64(MESSAGE)[:B64(NAT)][:B64(AUTH)][:TIMEOUT]:DIGEST
    /// ```
    pub fn encode(&self) -> Result<String, Error> {
        let fields = self.encode_fields()?;
        let digest = self.digest_type.digest_b64(fields.as_bytes());
        Ok(format!("{fields}:{digest}"))
    }

    fn encode_fields(&self) -> Result<String, Error> {
        validate_username(&self.username)?;
        match &self.request {
            Request::Command(cmd) => validate_command(cmd)?,
            Request::NatAccess { nat_access, .. } | Request::LocalNatAccess { nat_access, .. } => {
                validate_nat_access(nat_access)?
            }
            Request::Access { .. } => {}
        }

        let mut out = format!(
            "{}:{}:{}:{}:{}:{}",
            self.rand_val,
            b64::encode(self.username.as_bytes()),
            self.timestamp,
            PROTOCOL_VERSION,
            self.message_type().code(),
            b64::encode(self.request.message_text().as_bytes()),
        );
        if let Some(nat) = self.request.nat_access() {
            out.push(':');
            out.push_str(&b64::encode(nat.as_bytes()));
        }
        if let Some(auth) = self.server_auth.as_deref().filter(|a| !a.is_empty()) {
            out.push(':');
            out.push_str(&b64::encode(auth.as_bytes()));
        }
        if let Some(timeout) = self.request.client_timeout() {
            out.push(':');
            out.push_str(&timeout.to_string());
        }

        if !(MIN_ENCODED_LEN..=MAX_ENCODED_LEN).contains(&out.len()) {
            return Err(Error::MessageTooLarge(format!(
                "encoded message length {} out of range [{MIN_ENCODED_LEN}, {MAX_ENCODED_LEN}]",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Encodes, encrypts and (when the key set has an HMAC key) authenticates
    /// the message, returning the SPA data to send.
    pub fn encrypt(&self, keys: &KeySet) -> Result<SpaData, Error> {
        let plaintext = zeroize::Zeroizing::new(self.encode()?);
        let ciphertext = cipher::encrypt(
            keys.encryption_mode,
            plaintext.as_bytes(),
            keys.encryption_key.as_bytes(),
        )?;
        Ok(finish_spa_data(&ciphertext, keys))
    }

    #[cfg(test)]
    pub(crate) fn encrypt_with_salt(
        &self,
        keys: &KeySet,
        salt: &[u8; cipher::SALT_LEN],
    ) -> Result<SpaData, Error> {
        let plaintext = self.encode()?;
        let ciphertext = cipher::encrypt_with_salt(
            keys.encryption_mode,
            plaintext.as_bytes(),
            keys.encryption_key.as_bytes(),
            salt,
        );
        Ok(finish_spa_data(&ciphertext, keys))
    }

    /// Verifies the HMAC (when the key set has an HMAC key), decrypts and
    /// decodes SPA data.
    pub fn decrypt(data: &SpaData, keys: &KeySet) -> Result<SpaMessage, Error> {
        let wire = data.as_str().as_bytes();
        let mut full = B64_SALT_PREFIX.as_bytes().to_vec();

        match &keys.hmac {
            Some(hmac) => {
                let ciphertext = split_and_verify_hmac(wire, hmac.as_bytes(), hmac.hmac_type())?;
                full.extend_from_slice(ciphertext);
            }
            None => full.extend_from_slice(wire),
        }

        let ciphertext = b64::decode(&full)
            .map_err(|e| Error::DecryptionFailed(format!("base64 decode failed: {e}")))?;
        let plaintext = zeroize::Zeroizing::new(cipher::decrypt(
            keys.encryption_mode,
            &ciphertext,
            keys.encryption_key.as_bytes(),
        )?);
        decode_plaintext(&plaintext)
    }
}

/// Base64-encodes the ciphertext, drops the constant `Salted__` prefix and
/// appends the HMAC, which is computed over the base64 *with* the prefix
/// (see `fko_get_spa_data()` in C fwknop).
fn finish_spa_data(ciphertext: &[u8], keys: &KeySet) -> SpaData {
    let b64_full = b64::encode(ciphertext);
    let mut wire = b64_full[B64_SALT_PREFIX.len()..].to_string();
    if let Some(hmac) = &keys.hmac {
        wire.push_str(
            &hmac
                .hmac_type()
                .compute_b64(hmac.as_bytes(), b64_full.as_bytes()),
        );
    }
    SpaData::new(wire)
}

/// Splits `stripped_ciphertext || hmac` and checks the HMAC, returning the
/// stripped ciphertext.
fn split_and_verify_hmac<'a>(
    wire: &'a [u8],
    key: &[u8],
    hmac_type: HmacType,
) -> Result<&'a [u8], Error> {
    let hmac_len = hmac_type.b64_len();
    if wire.len() <= hmac_len {
        return Err(Error::HmacVerificationFailed);
    }
    let (ciphertext, received) = wire.split_at(wire.len() - hmac_len);
    let mut full = B64_SALT_PREFIX.as_bytes().to_vec();
    full.extend_from_slice(ciphertext);
    let computed = hmac_type.compute_b64(key, &full);
    if bool::from(computed.as_bytes().ct_eq(received)) {
        Ok(ciphertext)
    } else {
        Err(Error::HmacVerificationFailed)
    }
}

/// Parses decrypted plaintext into a message, checking the message digest and
/// then every field the way the encoder does.
pub(crate) fn decode_plaintext(plaintext: &[u8]) -> Result<SpaMessage, Error> {
    let last_colon = plaintext
        .iter()
        .rposition(|&c| c == b':')
        .ok_or_else(|| invalid("no fields found"))?;
    let (encoded, digest) = (&plaintext[..last_colon], &plaintext[last_colon + 1..]);
    let digest_type = verify_digest(encoded, digest)?;

    // The digest matched, so the fields are what the sender encoded; they
    // still have to be checked, since callers substitute them into commands.
    let encoded = std::str::from_utf8(encoded).map_err(|_| invalid("message is not valid text"))?;
    let fields: Vec<&str> = encoded.split(':').collect();
    if !(MIN_FIELDS..=MAX_FIELDS).contains(&fields.len()) {
        return Err(invalid(format!(
            "expected {MIN_FIELDS}-{MAX_FIELDS} fields, got {}",
            fields.len()
        )));
    }

    let rand_val_field = fields[0];
    let username = decode_text_field(fields[1], "username")?;
    let timestamp: i64 = fields[2]
        .parse()
        .map_err(|e| invalid(format!("invalid timestamp: {e}")))?;
    // fields[3] is the protocol version, which fwknop does not check.
    let type_code: i64 = fields[4]
        .parse()
        .map_err(|e| invalid(format!("invalid message type: {e}")))?;
    let message = decode_text_field(fields[5], "message")?;

    let message_type = MessageType::from_code(type_code)
        .ok_or_else(|| invalid(format!("invalid message type {type_code}")))?;

    let mut idx = 6;
    let mut nat_access = None;
    if idx < fields.len() && message_type.requires_nat_access() {
        nat_access = Some(decode_text_field(fields[idx], "NAT access")?);
        idx += 1;
    }

    // What follows is a client timeout (numeric) or server auth (base64),
    // optionally followed by a client timeout.
    let mut server_auth = None;
    let mut client_timeout = 0u32;
    if idx < fields.len() {
        if let Ok(t) = parse_go_uint32(fields[idx]) {
            client_timeout = t;
        } else {
            server_auth = Some(decode_text_field(fields[idx], "server auth")?);
            idx += 1;
            if idx < fields.len() {
                client_timeout = parse_go_uint32(fields[idx])
                    .map_err(|_| invalid(format!("invalid client timeout: {}", fields[idx])))?;
            }
        }
    }

    let rand_val: RandVal = rand_val_field.parse()?;
    validate_username(&username)?;
    let request = build_request(
        message_type,
        message,
        nat_access,
        NonZeroU32::new(client_timeout),
    )?;

    Ok(SpaMessage {
        rand_val,
        username,
        timestamp,
        request,
        server_auth,
        digest_type,
    })
}

fn build_request(
    message_type: MessageType,
    message: String,
    nat_access: Option<String>,
    client_timeout: Option<NonZeroU32>,
) -> Result<Request, Error> {
    if message_type == MessageType::Command {
        validate_command(&message)?;
        return Ok(Request::Command(message));
    }

    let access = AccessMessage::parse(&message, true)?;
    if message_type.requires_client_timeout() && client_timeout.is_none() {
        return Err(missing(format!(
            "message type {message_type} requires a client timeout"
        )));
    }
    let nat = || -> Result<String, Error> {
        let nat = nat_access.clone().unwrap_or_default();
        validate_nat_access(&nat)?;
        Ok(nat)
    };
    Ok(match message_type {
        MessageType::Access | MessageType::ClientTimeoutAccess => Request::Access {
            access,
            client_timeout,
        },
        MessageType::NatAccess | MessageType::ClientTimeoutNatAccess => Request::NatAccess {
            access,
            nat_access: nat()?,
            client_timeout,
        },
        MessageType::LocalNatAccess | MessageType::ClientTimeoutLocalNatAccess => {
            Request::LocalNatAccess {
                access,
                nat_access: nat()?,
                client_timeout,
            }
        }
        MessageType::Command => unreachable!("handled above"),
    })
}

/// Detects the digest type from the digest's length and verifies it. SHA-256
/// and SHA-512 digests that do not match are retried as SHA3-256 and
/// SHA3-512, which have the same lengths.
fn verify_digest(encoded: &[u8], digest: &[u8]) -> Result<DigestType, Error> {
    let candidates: &[DigestType] = match digest.len() {
        22 => &[DigestType::Md5],
        27 => &[DigestType::Sha1],
        43 => &[DigestType::Sha256, DigestType::Sha3_256],
        64 => &[DigestType::Sha384],
        86 => &[DigestType::Sha512, DigestType::Sha3_512],
        n => {
            return Err(Error::UnsupportedDigestType(format!(
                "unrecognized digest length {n}"
            )));
        }
    };
    for &candidate in candidates {
        let computed = candidate.digest_b64(encoded);
        if bool::from(computed.as_bytes().ct_eq(digest)) {
            return Ok(candidate);
        }
    }
    Err(Error::DigestVerificationFailed)
}

fn decode_text_field(field: &str, name: &str) -> Result<String, Error> {
    let bytes =
        b64::decode(field.as_bytes()).map_err(|e| invalid(format!("decoding {name}: {e}")))?;
    String::from_utf8(bytes).map_err(|_| invalid(format!("{name} is not valid UTF-8")))
}

/// Parses like Go's `strconv.ParseUint(s, 10, 32)`: ASCII digits only, no
/// sign.
fn parse_go_uint32(s: &str) -> Result<u32, ()> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    s.parse().map_err(|_| ())
}

/// A username must be non-empty, at most 64 bytes and made of printable,
/// non-space characters (C fwknop's `validate_username`).
fn validate_username(username: &str) -> Result<(), Error> {
    if username.is_empty() {
        return Err(missing("username is empty"));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(invalid("username too long"));
    }
    if !username.chars().all(is_printable_non_space) {
        return Err(invalid("username contains invalid character"));
    }
    Ok(())
}

/// Approximates Go's `unicode.IsPrint(r) && !unicode.IsSpace(r)`: rejects
/// control, whitespace, format and private-use characters. (Unlike Go it
/// does not reject unassigned code points; std has no table for them.)
fn is_printable_non_space(c: char) -> bool {
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    let cp = u32::from(c);
    let format_or_private = matches!(
        cp,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xE000..=0xF8FF
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
            | 0xF0000..=0x10FFFF
    );
    !format_or_private
}

fn validate_command(cmd: &str) -> Result<(), Error> {
    if cmd.is_empty() {
        return Err(missing("command message is empty"));
    }
    if cmd.len() > MAX_COMMAND_LEN {
        return Err(invalid("command message too long"));
    }
    Ok(())
}

fn validate_nat_access(nat: &str) -> Result<(), Error> {
    if nat.is_empty() {
        return Err(missing("NAT access is empty"));
    }
    if nat.len() > MAX_NAT_ACCESS_LEN {
        return Err(invalid("NAT access too long"));
    }
    Ok(())
}

fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}
