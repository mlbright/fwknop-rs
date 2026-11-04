//! Access stanzas from `access.yaml`.

use std::net::IpAddr;

use anyhow::{Result, anyhow, bail};
use ipnet::IpNet;
use serde::Deserialize;

use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet};

const DEFAULT_ACCESS_TIMEOUT: i64 = 30;
const DEFAULT_MAX_ACCESS_TIMEOUT: i64 = 300;

/// One access stanza as written in `access.yaml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RawStanza {
    pub source: String,
    pub open_ports: Vec<String>,
    pub key_base64: String,
    pub key: String,
    pub hmac_key_base64: String,
    pub hmac_key: String,
    pub hmac_digest_type: String,
    pub encryption_mode: String,
    pub access_timeout: i64,
    pub max_access_timeout: i64,
    pub require_username: String,
    pub require_source_address: bool,
    pub enable_cmd_exec: bool,
    pub cmd_exec_user: String,
}

/// An access stanza with its source networks and key set resolved.
#[derive(Debug, Clone)]
pub struct AccessStanza {
    /// As written (for `--dump-config`), including the unresolved
    /// `hmac_digest_type` and `encryption_mode` strings.
    pub raw: RawStanza,
    pub source_nets: Vec<IpNet>,
    pub keys: KeySet,
    /// With the 30-second default applied.
    pub access_timeout: i64,
    /// With the 300-second default applied.
    pub max_access_timeout: i64,
}

/// Reads and resolves `access.yaml`.
pub fn load_access_config(path: &str) -> Result<Vec<AccessStanza>> {
    let text =
        std::fs::read_to_string(path).map_err(|e| anyhow!("reading access file {path}: {e}"))?;
    parse_access_config(&text).map_err(|e| e.context(format!("access file {path}")))
}

pub fn parse_access_config(text: &str) -> Result<Vec<AccessStanza>> {
    let raws: Vec<RawStanza> = if is_empty_yaml(text) {
        Vec::new()
    } else {
        serde_saphyr::from_str::<Option<Vec<RawStanza>>>(text)
            .map_err(|e| anyhow!("parsing: {e}"))?
            .unwrap_or_default()
    };
    raws.into_iter()
        .enumerate()
        .map(|(i, raw)| {
            AccessStanza::resolve(raw).map_err(|e| anyhow!("access stanza {}: {e}", i + 1))
        })
        .collect()
}

fn is_empty_yaml(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .all(|l| l.is_empty() || l.starts_with('#') || l == "---")
}

impl AccessStanza {
    pub fn resolve(raw: RawStanza) -> Result<AccessStanza> {
        if raw.source.is_empty() {
            bail!("source is required");
        }
        let source_nets = parse_source_nets(&raw.source)?;

        let encryption_key = if !raw.key_base64.is_empty() {
            EncryptionKey::from_base64(&raw.key_base64)
                .map_err(|e| anyhow!("invalid key_base64: {e}"))?
        } else if !raw.key.is_empty() {
            EncryptionKey::new(raw.key.as_bytes())
        } else {
            bail!("encryption key is required (key or key_base64)");
        };

        let hmac_name = if raw.hmac_digest_type.is_empty() {
            "sha256"
        } else {
            &raw.hmac_digest_type
        };
        let hmac_type: HmacType = hmac_name
            .parse()
            .map_err(|_| anyhow!("unknown hmac_digest_type: {hmac_name}"))?;
        // Without an HMAC key, packets are accepted without an HMAC.
        let hmac = if !raw.hmac_key_base64.is_empty() {
            Some(
                HmacKey::from_base64(&raw.hmac_key_base64, hmac_type)
                    .map_err(|e| anyhow!("invalid hmac_key_base64: {e}"))?,
            )
        } else if !raw.hmac_key.is_empty() {
            Some(HmacKey::new(raw.hmac_key.as_bytes(), hmac_type))
        } else {
            None
        };

        let mode_name = if raw.encryption_mode.is_empty() {
            "cbc"
        } else {
            &raw.encryption_mode
        };
        let encryption_mode: EncryptionMode = mode_name
            .parse()
            .map_err(|_| anyhow!("unknown encryption_mode: {mode_name}"))?;

        let access_timeout = if raw.access_timeout == 0 {
            DEFAULT_ACCESS_TIMEOUT
        } else {
            raw.access_timeout
        };
        let max_access_timeout = if raw.max_access_timeout == 0 {
            DEFAULT_MAX_ACCESS_TIMEOUT
        } else {
            raw.max_access_timeout
        };

        Ok(AccessStanza {
            raw,
            source_nets,
            keys: KeySet::new(encryption_key, encryption_mode, hmac),
            access_timeout,
            max_access_timeout,
        })
    }

    /// Whether a packet from `src` should be tried against this stanza.
    pub fn matches_source(&self, src: IpAddr) -> bool {
        let src = src.to_canonical();
        self.source_nets.iter().any(|n| n.contains(&src))
    }

    /// Whether `proto/port` is allowed by `open_ports` (an empty list allows
    /// everything).
    pub fn allows_port(&self, proto: &str, port: &str) -> bool {
        if self.raw.open_ports.is_empty() {
            return true;
        }
        let requested = format!("{proto}/{port}");
        self.raw
            .open_ports
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&requested))
    }
}

/// `ANY`, or a comma-separated list of IPs and CIDRs. A bare IP is a /32
/// (IPv4) or /128 (IPv6).
fn parse_source_nets(source: &str) -> Result<Vec<IpNet>> {
    if source.eq_ignore_ascii_case("ANY") {
        return Ok(vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]);
    }
    source
        .split(',')
        .map(str::trim)
        .map(|part| {
            let cidr = if part.contains('/') {
                part.to_string()
            } else if part.parse::<IpAddr>().is_ok() && part.contains(':') {
                format!("{part}/128")
            } else {
                format!("{part}/32")
            };
            let net: IpNet = cidr
                .parse()
                .map_err(|_| anyhow!("invalid source {cidr:?}: invalid CIDR address: {cidr}"))?;
            // An IPv4-mapped IPv6 network matches the IPv4 addresses it maps.
            Ok(match net {
                IpNet::V6(v6) => match v6.addr().to_ipv4_mapped() {
                    Some(v4) if v6.prefix_len() >= 96 => {
                        IpNet::new(IpAddr::V4(v4), v6.prefix_len() - 96).unwrap()
                    }
                    _ => net,
                },
                v4 => v4,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(yaml: &str) -> Result<AccessStanza> {
        parse_access_config(yaml).map(|mut v| v.remove(0))
    }

    fn with_source(source: &str) -> AccessStanza {
        stanza(&format!("- source: \"{source}\"\n  key: k\n")).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn match_source_cidr() {
        let s = with_source("192.168.1.0/24");
        assert!(s.matches_source(ip("192.168.1.50")));
        assert!(!s.matches_source(ip("192.168.2.1")));
        // Host bits in the CIDR are ignored, as Go's ParseCIDR does.
        assert!(with_source("192.168.1.5/24").matches_source(ip("192.168.1.200")));
    }

    #[test]
    fn match_source_any() {
        let s = with_source("ANY");
        assert!(s.matches_source(ip("1.2.3.4")));
        assert!(s.matches_source(ip("2001:db8::1")));
        assert!(with_source("any").matches_source(ip("10.0.0.1")));
    }

    #[test]
    fn match_source_ipv6() {
        let s = with_source("2001:db8::1");
        assert!(s.matches_source(ip("2001:db8::1")));
        assert!(!s.matches_source(ip("2001:db8::2")));
        let s = with_source("2001:db8::/32");
        assert!(s.matches_source(ip("2001:db8:ffff::1")));
        assert!(!s.matches_source(ip("2001:db9::1")));
        assert!(!s.matches_source(ip("10.0.0.1")));
    }

    #[test]
    fn match_source_single_and_multiple() {
        let s = with_source("10.0.0.1");
        assert!(s.matches_source(ip("10.0.0.1")));
        assert!(!s.matches_source(ip("10.0.0.2")));
        let s = with_source("10.0.0.1, 192.168.1.0/24,2001:db8::/64");
        assert!(s.matches_source(ip("10.0.0.1")));
        assert!(s.matches_source(ip("192.168.1.9")));
        assert!(s.matches_source(ip("2001:db8::9")));
        assert!(!s.matches_source(ip("172.16.0.1")));
    }

    #[test]
    fn ipv4_mapped_packet_sources_match_ipv4_networks() {
        // A dual-stack socket reports IPv4 senders as ::ffff:a.b.c.d.
        let s = with_source("127.0.0.0/8");
        assert!(s.matches_source(ip("::ffff:127.0.0.1")));
        assert!(!with_source("::/0").matches_source(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn resolve_keys() {
        let s =
            stanza("- source: ANY\n  key_base64: dGVzdGtleQ==\n  hmac_key_base64: aG1hY2tleQ==\n")
                .unwrap();
        assert_eq!(s.keys.encryption_key.len(), 7);
        assert_eq!(s.keys.hmac.as_ref().unwrap().len(), 7);
        let s = stanza("- source: ANY\n  key: plain\n  hmac_key: hplain\n").unwrap();
        assert_eq!(s.keys.encryption_key.as_bytes(), b"plain");
        assert_eq!(s.keys.hmac.as_ref().unwrap().as_bytes(), b"hplain");
        let s = stanza("- source: ANY\n  key: plain\n").unwrap();
        assert!(s.keys.hmac.is_none());
        let err = stanza("- source: ANY\n").unwrap_err();
        assert!(
            err.to_string().contains("encryption key is required"),
            "{err}"
        );
    }

    #[test]
    fn resolve_hmac_type_and_mode() {
        let s = stanza("- source: ANY\n  key: k\n  hmac_key: h\n").unwrap();
        assert_eq!(s.keys.hmac.unwrap().hmac_type(), HmacType::Sha256);
        let s = stanza("- source: ANY\n  key: k\n  hmac_key: h\n  hmac_digest_type: SHA3-512\n")
            .unwrap();
        assert_eq!(s.keys.hmac.unwrap().hmac_type(), HmacType::Sha3_512);
        assert!(stanza("- source: ANY\n  key: k\n  hmac_digest_type: bogus\n").is_err());

        assert_eq!(
            stanza("- source: ANY\n  key: k\n")
                .unwrap()
                .keys
                .encryption_mode,
            EncryptionMode::Cbc
        );
        assert_eq!(
            stanza("- source: ANY\n  key: k\n  encryption_mode: legacy\n")
                .unwrap()
                .keys
                .encryption_mode,
            EncryptionMode::CbcLegacyIv
        );
        let err = stanza("- source: ANY\n  key: k\n  encryption_mode: ecb\n").unwrap_err();
        assert!(
            err.to_string().contains("unknown encryption_mode: ecb"),
            "{err}"
        );
    }

    #[test]
    fn timeouts_default() {
        let s = stanza("- source: ANY\n  key: k\n").unwrap();
        assert_eq!((s.access_timeout, s.max_access_timeout), (30, 300));
        let s = stanza("- source: ANY\n  key: k\n  access_timeout: 60\n  max_access_timeout: 90\n")
            .unwrap();
        assert_eq!((s.access_timeout, s.max_access_timeout), (60, 90));
    }

    #[test]
    fn invalid_and_empty_source() {
        let err = stanza("- source: not-an-ip\n  key: k\n").unwrap_err();
        assert!(err.to_string().contains("invalid source"), "{err}");
        let err = stanza("- key: k\n").unwrap_err();
        assert!(err.to_string().contains("source is required"), "{err}");
        assert!(err.to_string().starts_with("access stanza 1:"), "{err}");
    }

    #[test]
    fn invalid_base64_key() {
        let err = stanza("- source: ANY\n  key_base64: '!!!'\n").unwrap_err();
        assert!(err.to_string().contains("invalid key_base64"), "{err}");
    }

    #[test]
    fn yaml_1_1_booleans_and_numbers_in_typed_fields() {
        // yaml.v3 accepts these when decoding into typed fields.
        let s = stanza(
            "- source: ANY\n  key: 12345\n  require_source_address: yes\n  enable_cmd_exec: on\n  require_username: no\n",
        )
        .unwrap();
        assert!(s.raw.require_source_address);
        assert!(s.raw.enable_cmd_exec);
        assert_eq!(s.keys.encryption_key.as_bytes(), b"12345");
        assert_eq!(s.raw.require_username, "no");
    }

    #[test]
    fn load_file_and_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.yaml");
        std::fs::write(
            &path,
            "- source: \"192.168.1.0/24\"\n  open_ports:\n    - tcp/22\n  key: a\n- source: ANY\n  key: b\n  unknown_key: ignored\n",
        )
        .unwrap();
        let stanzas = load_access_config(path.to_str().unwrap()).unwrap();
        assert_eq!(stanzas.len(), 2);
        assert_eq!(stanzas[0].raw.open_ports, ["tcp/22"]);

        let err = load_access_config("/nonexistent/access.yaml").unwrap_err();
        assert!(err.to_string().starts_with("reading access file"), "{err}");

        std::fs::write(&path, "- source: [unclosed\n").unwrap();
        assert!(load_access_config(path.to_str().unwrap()).is_err());

        std::fs::write(&path, "# nothing\n").unwrap();
        assert!(
            load_access_config(path.to_str().unwrap())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn allows_port() {
        let s = stanza("- source: ANY\n  key: k\n  open_ports: [tcp/22, UDP/53]\n").unwrap();
        assert!(s.allows_port("tcp", "22"));
        assert!(s.allows_port("udp", "53"));
        assert!(!s.allows_port("tcp", "443"));
        assert!(with_source("ANY").allows_port("tcp", "12345"));
    }

    #[test]
    fn sample_access_files_parse() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for rel in [
            "conf_files/access.yaml",
            "examples/configs/access-basic.yaml",
            "examples/configs/access-multi.yaml",
            "test/interop/access.yaml",
        ] {
            let path = root.join(rel);
            if path.exists() {
                load_access_config(path.to_str().unwrap())
                    .unwrap_or_else(|e| panic!("{rel}: {e:#}"));
            }
        }
    }
}
