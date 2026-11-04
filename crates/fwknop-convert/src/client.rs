//! Legacy C `.fwknoprc` (INI-style `[stanza]` / `KEY value`) to YAML rc
//! stanzas.

use std::collections::BTreeMap;

use crate::yaml::{Val, parse_bool, scalar, split_key_value, write_mapping};

pub type ClientStanzas = BTreeMap<String, BTreeMap<String, Val>>;

/// Parses rc stanzas. Lines before the first `[stanza]` header belong to
/// `default`, which always exists.
pub fn parse_client_stanzas(data: &str) -> (ClientStanzas, Vec<String>) {
    let mut stanzas: ClientStanzas = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut current = "default".to_string();
    stanzas.insert(current.clone(), BTreeMap::new());

    for line in data.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_string();
            stanzas.entry(current.clone()).or_default();
            continue;
        }
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        match map_client_key(key) {
            Some(mapped) => {
                stanzas
                    .get_mut(&current)
                    .expect("current rc stanza exists")
                    .insert(mapped.to_string(), client_value(mapped, value));
            }
            None => warnings.push(format!(
                "skipping unsupported key {key} in stanza [{current}]"
            )),
        }
    }
    (stanzas, warnings)
}

/// Typed values, so the YAML loads: fwknop-go wrote `use_hmac: Y`, which
/// its own client then rejected.
fn client_value(key: &str, value: &str) -> Val {
    match key {
        "use_hmac" | "nat_local" | "resolve_ip" => Val::Bool(parse_bool(value)),
        "server_port" | "fw_timeout" => Val::int_or_str(value),
        "verbose" => match value.parse::<i64>() {
            Ok(n) => Val::Int(n),
            Err(_) => Val::Bool(parse_bool(value)),
        },
        _ => Val::Str(value.to_string()),
    }
}

/// C `.fwknoprc` keys to rc stanza keys; `None` for keys with no
/// equivalent.
pub fn map_client_key(key: &str) -> Option<&'static str> {
    Some(match key.to_ascii_uppercase().as_str() {
        "SPA_SERVER" => "destination",
        "SPA_SERVER_PORT" => "server_port",
        "ACCESS" => "access",
        "ALLOW_IP" => "allow_ip",
        "DIGEST_TYPE" => "digest_type",
        "HMAC_DIGEST_TYPE" => "hmac_digest_type",
        "ENCRYPTION_MODE" => "encryption_mode",
        "KEY" => "key",
        "KEY_BASE64" => "key_base64",
        "HMAC_KEY" => "key_hmac",
        "HMAC_KEY_BASE64" => "hmac_key_base64",
        "USE_HMAC" => "use_hmac",
        "FW_TIMEOUT" => "fw_timeout",
        "SPOOF_USER" => "spoof_user",
        "NAT_ACCESS" => "nat_access",
        "NAT_LOCAL" => "nat_local",
        "RESOLVE_IP_HTTPS" | "RESOLVE_IP_HTTP" => "resolve_ip",
        "RESOLVE_URL" => "resolve_url",
        "VERBOSE" => "verbose",
        // SPA_SERVER_PROTO (UDP only) and NAT_PORT (never used) are
        // dropped, like any unknown key.
        _ => return None,
    })
}

/// The YAML: `default` first, then the other rc stanzas by name, keys
/// sorted.
pub fn render_client(stanzas: &ClientStanzas) -> String {
    let mut names: Vec<&String> = stanzas.keys().filter(|n| *n != "default").collect();
    names.sort();
    let mut out = String::new();
    for name in std::iter::once(&"default".to_string()).chain(names) {
        let Some(values) = stanzas.get(name) else {
            continue;
        };
        if values.is_empty() {
            out.push_str(&format!("{}: {{}}\n", scalar(name)));
            continue;
        }
        out.push_str(&format!("{}:\n", scalar(name)));
        let entries: Vec<(String, Val)> =
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        write_mapping(&mut out, &entries, 2);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RC: &str = "\
# A legacy rc file
[default]
SPA_SERVER      192.168.1.100
ACCESS          tcp/22
KEY_BASE64      dGVzdGtleQ==
HMAC_KEY_BASE64 aG1hY2tleQ==
USE_HMAC        Y
VERBOSE         Y

[production]
SPA_SERVER      prod.example.com
SPA_SERVER_PORT 62201
FW_TIMEOUT      60
NAT_PORT        2222
GPG_RECIPIENT   someone
RESOLVE_IP_HTTPS Y
";

    #[test]
    fn converts_stanzas_and_keys() {
        let (stanzas, warnings) = parse_client_stanzas(RC);
        let d = &stanzas["default"];
        assert_eq!(d["destination"], Val::Str("192.168.1.100".into()));
        assert_eq!(d["access"], Val::Str("tcp/22".into()));
        assert_eq!(d["key_base64"], Val::Str("dGVzdGtleQ==".into()));
        assert_eq!(d["hmac_key_base64"], Val::Str("aG1hY2tleQ==".into()));
        assert_eq!(d["use_hmac"], Val::Bool(true));
        assert_eq!(d["verbose"], Val::Bool(true));
        let p = &stanzas["production"];
        assert_eq!(p["server_port"], Val::Int(62201));
        assert_eq!(p["fw_timeout"], Val::Int(60));
        assert_eq!(p["resolve_ip"], Val::Bool(true));
        assert!(!p.contains_key("nat_port"));
        assert_eq!(
            warnings,
            [
                "skipping unsupported key NAT_PORT in stanza [production]",
                "skipping unsupported key GPG_RECIPIENT in stanza [production]"
            ]
        );
    }

    #[test]
    fn key_mapping() {
        assert_eq!(map_client_key("spa_server"), Some("destination"));
        assert_eq!(map_client_key("HMAC_KEY"), Some("key_hmac"));
        assert_eq!(map_client_key("RESOLVE_IP_HTTP"), Some("resolve_ip"));
        assert_eq!(map_client_key("SPA_SERVER_PROTO"), None);
        assert_eq!(map_client_key("NAT_PORT"), None);
        assert_eq!(map_client_key("BOGUS"), None);
    }

    #[test]
    fn renders_default_first_then_sorted() {
        let (stanzas, _) = parse_client_stanzas("[zeta]\nACCESS tcp/1\n[alpha]\nACCESS tcp/2\n");
        let out = render_client(&stanzas);
        assert_eq!(
            out,
            "default: {}\nalpha:\n  access: tcp/2\nzeta:\n  access: tcp/1\n"
        );
    }

    #[test]
    fn output_loads_as_an_rc_file() {
        let (stanzas, _) = parse_client_stanzas(RC);
        let out = render_client(&stanzas);
        let raw = cli_common::layers::parse_untyped_yaml(&out).unwrap();
        let cli_common::layers::Raw::Map(entries) = raw else {
            panic!()
        };
        assert_eq!(entries[0].0, "default");
        let mut layers = cli_common::layers::Layers::new();
        let cli_common::layers::Raw::Map(default) = entries[0].1.clone() else {
            panic!()
        };
        layers.load_map(default);
        assert!(layers.bool("use_hmac").unwrap());
        assert_eq!(layers.int("verbose").unwrap(), 1);
        assert_eq!(layers.string("destination").unwrap(), "192.168.1.100");
    }
}
