//! Legacy C `access.conf` to `access.yaml`. Each `SOURCE` line starts a new
//! access stanza.

use std::collections::BTreeMap;

use crate::yaml::{Val, parse_bool, split_key_value, write_mapping};

pub type AccessStanzas = Vec<BTreeMap<String, Val>>;

pub fn parse_access_config(data: &str) -> (AccessStanzas, Vec<String>) {
    let mut stanzas: AccessStanzas = Vec::new();
    let mut warnings = Vec::new();
    let mut current: Option<BTreeMap<String, Val>> = None;

    for (i, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("%include") {
            let directive = line.split(' ').next().unwrap_or(line);
            warnings.push(format!(
                "line {}: {directive} directive not resolved; manually merge the included file",
                i + 1
            ));
            continue;
        }
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        let value = value.trim_end_matches(';').trim();
        let upper = key.to_ascii_uppercase();

        if upper == "SOURCE" {
            if let Some(done) = current.take() {
                stanzas.push(done);
            }
            current = Some(BTreeMap::from([(
                "source".to_string(),
                Val::Str(value.to_string()),
            )]));
            continue;
        }
        let stanza = current.get_or_insert_with(BTreeMap::new);
        match classify_access_key(&upper) {
            Action::Convert(target) => {
                stanza.insert(target.to_string(), access_value(target, value));
            }
            Action::ConvertBool(target) => {
                stanza.insert(target.to_string(), Val::Bool(parse_bool(value)));
            }
            Action::ConvertList(target) => {
                stanza.insert(target.to_string(), Val::List(parse_port_list(value)));
            }
            Action::Warn(reason) => warnings.push(format!("{reason}: key {key} skipped")),
            Action::Unknown => warnings.push(format!("unrecognized key {key}")),
        }
    }
    if let Some(done) = current {
        stanzas.push(done);
    }
    (stanzas, warnings)
}

/// The timeouts as integers: fwknop-go wrote `access_timeout: "30"`, which
/// its own server then refused to load.
fn access_value(key: &str, value: &str) -> Val {
    match key {
        "access_timeout" | "max_access_timeout" => Val::int_or_str(value),
        _ => Val::Str(value.to_string()),
    }
}

enum Action {
    Convert(&'static str),
    ConvertBool(&'static str),
    ConvertList(&'static str),
    Warn(&'static str),
    Unknown,
}

fn classify_access_key(upper: &str) -> Action {
    match upper {
        "SOURCE" => Action::Convert("source"),
        "DESTINATION" => Action::Convert("destination"),
        "KEY" => Action::Convert("key"),
        "KEY_BASE64" => Action::Convert("key_base64"),
        "HMAC_KEY" => Action::Convert("hmac_key"),
        "HMAC_KEY_BASE64" => Action::Convert("hmac_key_base64"),
        "HMAC_DIGEST_TYPE" => Action::Convert("hmac_digest_type"),
        "ENCRYPTION_MODE" => Action::Convert("encryption_mode"),
        "FW_ACCESS_TIMEOUT" => Action::Convert("access_timeout"),
        "MAX_FW_TIMEOUT" => Action::Convert("max_access_timeout"),
        "REQUIRE_USERNAME" => Action::Convert("require_username"),
        "CMD_EXEC_USER" => Action::Convert("cmd_exec_user"),
        "CMD_EXEC_GROUP" => Action::Convert("cmd_exec_group"),
        "CMD_SUDO_EXEC_USER" => Action::Convert("cmd_sudo_exec_user"),
        "CMD_SUDO_EXEC_GROUP" => Action::Convert("cmd_sudo_exec_group"),
        "ACCESS_EXPIRE" => Action::Convert("access_expire"),
        "ACCESS_EXPIRE_EPOCH" => Action::Convert("access_expire_epoch"),
        "CMD_CYCLE_OPEN" => Action::Convert("cmd_cycle_open"),
        "CMD_CYCLE_CLOSE" => Action::Convert("cmd_cycle_close"),
        "CMD_CYCLE_TIMER" => Action::Convert("cmd_cycle_timer"),

        "REQUIRE_SOURCE_ADDRESS" | "REQUIRE_SOURCE" => {
            Action::ConvertBool("require_source_address")
        }
        "ENABLE_CMD_EXEC" => Action::ConvertBool("enable_cmd_exec"),
        "ENABLE_CMD_SUDO_EXEC" => Action::ConvertBool("enable_cmd_sudo_exec"),
        "FORCE_NAT" => Action::ConvertBool("force_nat"),
        "FORCE_SNAT" => Action::ConvertBool("force_snat"),
        "FORCE_MASQUERADE" => Action::ConvertBool("force_masquerade"),
        "DISABLE_DNAT" => Action::ConvertBool("disable_dnat"),
        "FORWARD_ALL" => Action::ConvertBool("forward_all"),

        "OPEN_PORTS" => Action::ConvertList("open_ports"),
        "RESTRICT_PORTS" => Action::ConvertList("restrict_ports"),

        "GPG_HOME_DIR"
        | "GPG_EXE"
        | "GPG_DECRYPT_ID"
        | "GPG_DECRYPT_PW"
        | "GPG_REQUIRE_SIG"
        | "GPG_DISABLE_SIG"
        | "GPG_IGNORE_SIG_VERIFY_ERROR"
        | "GPG_REMOTE_ID"
        | "GPG_FINGERPRINT_ID"
        | "GPG_ALLOW_NO_PW" => Action::Warn("GPG support not available in fwknop-rs"),
        _ => Action::Unknown,
    }
}

fn parse_port_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// The YAML: a list of access stanzas, keys sorted.
pub fn render_access(stanzas: &AccessStanzas) -> String {
    let mut out = String::new();
    for stanza in stanzas {
        let entries: Vec<(String, Val)> =
            stanza.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        if entries.is_empty() {
            out.push_str("- {}\n");
            continue;
        }
        let mut body = String::new();
        write_mapping(&mut body, &entries, 2);
        // The first key goes on the "- " line.
        out.push_str("- ");
        out.push_str(body.trim_start_matches("  "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCESS: &str = "\
SOURCE                ANY
KEY_BASE64            dGVzdGtleQ==
HMAC_KEY_BASE64       aG1hY2tleQ==
FW_ACCESS_TIMEOUT     30;
OPEN_PORTS            tcp/22, udp/53
REQUIRE_SOURCE_ADDRESS Y

SOURCE                192.168.1.0/24
KEY                   plainkey
ENABLE_CMD_EXEC       N
MAX_FW_TIMEOUT        600
GPG_DECRYPT_ID        ABCD
WHATEVER              1
%include_folder /etc/fwknop/access.d
";

    #[test]
    fn converts_stanzas() {
        let (stanzas, warnings) = parse_access_config(ACCESS);
        assert_eq!(stanzas.len(), 2);
        let a = &stanzas[0];
        assert_eq!(a["source"], Val::Str("ANY".into()));
        assert_eq!(a["access_timeout"], Val::Int(30));
        assert_eq!(
            a["open_ports"],
            Val::List(vec!["tcp/22".into(), "udp/53".into()])
        );
        assert_eq!(a["require_source_address"], Val::Bool(true));
        let b = &stanzas[1];
        assert_eq!(b["enable_cmd_exec"], Val::Bool(false));
        assert_eq!(b["max_access_timeout"], Val::Int(600));
        assert_eq!(
            warnings,
            [
                "GPG support not available in fwknop-rs: key GPG_DECRYPT_ID skipped",
                "unrecognized key WHATEVER",
                "line 14: %include_folder directive not resolved; manually merge the included file",
            ]
        );
    }

    #[test]
    fn synonyms_and_expire_and_cycle_keys() {
        let (stanzas, warnings) = parse_access_config(
            "SOURCE ANY\nREQUIRE_SOURCE Y\nACCESS_EXPIRE 01/01/2030\nACCESS_EXPIRE_EPOCH 1893456000\n\
             CMD_CYCLE_OPEN echo open\nCMD_CYCLE_CLOSE echo close\nCMD_CYCLE_TIMER 30\n\
             FORCE_NAT 10.0.0.1 22\nRESTRICT_PORTS tcp/23\nDESTINATION ANY\n",
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        let s = &stanzas[0];
        assert_eq!(s["require_source_address"], Val::Bool(true));
        assert_eq!(s["access_expire"], Val::Str("01/01/2030".into()));
        assert_eq!(s["cmd_cycle_open"], Val::Str("echo open".into()));
        assert_eq!(s["restrict_ports"], Val::List(vec!["tcp/23".into()]));
        assert_eq!(s["destination"], Val::Str("ANY".into()));
    }

    #[test]
    fn output_loads_as_access_stanzas() {
        let (stanzas, _) = parse_access_config(ACCESS);
        let out = render_access(&stanzas);
        #[derive(serde::Deserialize, Debug)]
        struct S {
            source: String,
            #[serde(default)]
            access_timeout: i64,
            #[serde(default)]
            open_ports: Vec<String>,
            #[serde(default)]
            require_source_address: bool,
        }
        let parsed: Vec<S> = serde_saphyr::from_str(&out).unwrap_or_else(|e| panic!("{e}\n{out}"));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].source, "ANY");
        assert_eq!(parsed[0].access_timeout, 30);
        assert_eq!(parsed[0].open_ports, ["tcp/22", "udp/53"]);
        assert!(parsed[0].require_source_address);
        assert_eq!(parsed[1].source, "192.168.1.0/24");
    }

    #[test]
    fn render_shape() {
        let (stanzas, _) = parse_access_config("SOURCE ANY\nKEY k\nOPEN_PORTS tcp/22\n");
        assert_eq!(
            render_access(&stanzas),
            "- key: k\n  open_ports:\n    - tcp/22\n  source: ANY\n"
        );
    }
}
