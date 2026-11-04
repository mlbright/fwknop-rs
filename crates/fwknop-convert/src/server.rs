//! Legacy C `fwknopd.conf` to `server.yaml`.

use std::collections::BTreeMap;

use crate::yaml::{Val, parse_bool, split_key_value, write_mapping};

#[derive(Debug, Default)]
pub struct ServerConversion {
    pub config: BTreeMap<String, Val>,
    pub warnings: Vec<String>,
    /// The Linux firewall the legacy config was written for, if its keys
    /// show it.
    pub firewall: Option<&'static str>,
    /// Keys for firewalls fwknop-rs does not support (ipfw, pf), by
    /// firewall.
    unsupported: std::collections::BTreeMap<&'static str, Vec<String>>,
}

pub fn parse_server_config(data: &str) -> ServerConversion {
    let mut conv = ServerConversion::default();
    for line in data.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        let value = value.trim_end_matches(';').trim();
        let upper = key.to_ascii_uppercase();

        if let Some(fw) = firewall_for_key(&upper) {
            if matches!(fw, "ipfw" | "pf") {
                conv.unsupported
                    .entry(fw)
                    .or_default()
                    .push(key.to_string());
            } else {
                // Like fwknop-go, firewalld keys win over iptables keys.
                conv.firewall = Some(match conv.firewall {
                    Some(prev) if fw == "iptables" => prev,
                    _ => fw,
                });
            }
            continue;
        }
        if upper.starts_with("NFQ_") || upper.starts_with("ENABLE_NFQ_") {
            conv.warnings.push(format!(
                "NFQ capture not supported; key {key} skipped (use UDP server mode)"
            ));
            continue;
        }

        match classify_server_key(&upper) {
            Action::Convert(target) => {
                conv.config
                    .insert(target.to_string(), server_value(target, value));
            }
            Action::ConvertBool(target) => {
                conv.config
                    .insert(target.to_string(), Val::Bool(parse_bool(value)));
            }
            Action::Ignore => {}
            Action::Warn(reason) => conv.warnings.push(format!("{reason}: key {key} skipped")),
            Action::Unknown => conv.warnings.push(format!("unrecognized key {key}")),
        }
    }
    for (fw, keys) in std::mem::take(&mut conv.unsupported) {
        conv.warnings.push(format!(
            "{fw} firewall configuration skipped ({}): fwknop-rs supports Linux only; \
             use action_template: nftables.yaml or iptables.yaml",
            keys.join(", ")
        ));
    }
    if let Some(fw) = conv.firewall {
        conv.config
            .insert("action_template".into(), Val::Str(format!("{fw}.yaml")));
    }
    conv
}

/// Typed values: the port and age as integers, and `verbose` as the bool
/// fwknopd expects (C allowed a level such as `2`, which fwknop-go's server
/// could not read).
fn server_value(key: &str, value: &str) -> Val {
    match key {
        "udp_port" | "max_spa_packet_age" => Val::int_or_str(value),
        "verbose" => match value.parse::<i64>() {
            Ok(n) => Val::Bool(n != 0),
            Err(_) => Val::Bool(parse_bool(value)),
        },
        _ => Val::Str(value.to_string()),
    }
}

fn firewall_for_key(upper: &str) -> Option<&'static str> {
    if upper.starts_with("IPT_")
        || upper.starts_with("ENABLE_IPT_")
        || upper.starts_with("FLUSH_IPT_")
    {
        Some("iptables")
    } else if upper.starts_with("FIREWD_")
        || upper.starts_with("ENABLE_FIREWD_")
        || upper.starts_with("FLUSH_FIREWD_")
    {
        Some("firewalld")
    } else if upper.starts_with("IPFW_") || upper.starts_with("FLUSH_IPFW_") {
        Some("ipfw")
    } else if upper.starts_with("PF_") {
        Some("pf")
    } else {
        None
    }
}

enum Action {
    Convert(&'static str),
    ConvertBool(&'static str),
    Ignore,
    Warn(&'static str),
    Unknown,
}

fn classify_server_key(upper: &str) -> Action {
    match upper {
        "UDPSERV_PORT" => Action::Convert("udp_port"),
        "VERBOSE" => Action::Convert("verbose"),
        "MAX_SPA_PACKET_AGE" => Action::Convert("max_spa_packet_age"),
        "SYSLOG_IDENTITY" => Action::Convert("syslog_identity"),
        "SYSLOG_FACILITY" => Action::Convert("syslog_facility"),
        "FWKNOP_PID_FILE" => Action::Convert("pid_file"),
        "ACCESS_FILE" => Action::Convert("access_file"),

        "ENABLE_SPA_PACKET_AGING" => Action::ConvertBool("enable_spa_packet_aging"),
        "ENABLE_DIGEST_PERSISTENCE" => Action::ConvertBool("enable_digest_persistence"),

        "FWKNOP_RUN_DIR" => Action::Warn("not used by fwknopd"),

        // pcap capture (fwknopd uses UDP server mode)
        "PCAP_INTF"
        | "PCAP_FILTER"
        | "PCAP_DISPATCH_COUNT"
        | "PCAP_LOOP_SLEEP"
        | "MAX_SNIFF_BYTES"
        | "ENABLE_PCAP_PROMISC"
        | "ENABLE_PCAP_ANY_DIRECTION"
        | "EXIT_AT_INTF_DOWN" => Action::Ignore,
        // always on, or not applicable
        "ENABLE_UDP_SERVER"
        | "UDPSERV_SELECT_TIMEOUT"
        | "FWKNOP_CONF_DIR"
        | "ACCESS_FOLDER"
        | "DIGEST_FILE"
        | "DIGEST_DB_FILE"
        | "RULES_CHECK_THRESHOLD"
        | "CMD_EXEC_TIMEOUT" => Action::Ignore,
        // firewall rule details (handled by action templates)
        "ENABLE_RULE_PREPEND"
        | "ENABLE_DESTINATION_RULE"
        | "ENABLE_NAT_DNS"
        | "FIREWALL_EXE"
        | "SNAT_TRANSLATE_IP"
        | "ENABLE_FIREWD_COMMENT_CHECK"
        | "ENABLE_IPT_COMMENT_CHECK" => Action::Ignore,

        "GPG_HOME_DIR" | "GPG_EXE" => Action::Warn("GPG encryption not supported in fwknop-rs"),
        "ENABLE_SPA_OVER_HTTP" | "ALLOW_ANY_USER_AGENT" | "ENABLE_X_FORWARDED_FOR" => {
            Action::Warn("HTTP SPA mode not supported")
        }
        "ENABLE_TCP_SERVER" | "TCPSERV_PORT" => {
            Action::Warn("TCP server mode not supported; use UDP")
        }
        "ENABLE_EXTERNAL_CMDS"
        | "EXTERNAL_CMD_OPEN"
        | "EXTERNAL_CMD_CLOSE"
        | "EXTERNAL_CMD_ALARM"
        | "ENABLE_EXT_CMD_PREFIX"
        | "EXT_CMD_PREFIX" => Action::Warn("use action templates instead of external commands"),
        "PCAP_FILE" => Action::Warn("pcap file replay not supported"),
        "LOCALE" => Action::Warn("locale override not applicable"),
        _ => Action::Unknown,
    }
}

/// The YAML, keys sorted, with a comment naming the detected firewall.
pub fn render_server(conv: &ServerConversion) -> String {
    let mut out = String::new();
    if let Some(fw) = conv.firewall {
        out.push_str(&format!(
            "# Detected {fw} firewall configuration from legacy config.\n"
        ));
    }
    let entries: Vec<(String, Val)> = conv
        .config
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if entries.is_empty() {
        out.push_str("{}\n");
    } else {
        write_mapping(&mut out, &entries, 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_keys_and_semicolons() {
        let conv = parse_server_config(
            "UDPSERV_PORT    62201;\nVERBOSE  1;\nMAX_SPA_PACKET_AGE 120;\nSYSLOG_IDENTITY       fwknopd;\n",
        );
        assert!(conv.warnings.is_empty(), "{:?}", conv.warnings);
        assert_eq!(conv.config["udp_port"], Val::Int(62201));
        assert_eq!(conv.config["verbose"], Val::Bool(true));
        assert_eq!(conv.config["max_spa_packet_age"], Val::Int(120));
        assert_eq!(conv.config["syslog_identity"], Val::Str("fwknopd".into()));
    }

    #[test]
    fn pcap_keys_are_silently_ignored() {
        let conv = parse_server_config(
            "UDPSERV_PORT 62201;\nPCAP_INTF eth0;\nPCAP_FILTER udp port 62201;\nENABLE_PCAP_PROMISC N;\n",
        );
        assert!(conv.warnings.is_empty());
        assert_eq!(conv.config.len(), 1);
    }

    #[test]
    fn firewall_detection() {
        let conv = parse_server_config(
            "UDPSERV_PORT 62201;\nIPT_INPUT_ACCESS ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1;\nENABLE_IPT_FORWARDING N;\n",
        );
        assert_eq!(conv.firewall, Some("iptables"));
        assert!(conv.warnings.is_empty());
        assert_eq!(
            conv.config["action_template"],
            Val::Str("iptables.yaml".into())
        );
        for (input, want) in [
            (
                "FIREWD_INPUT_ACCESS ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1;\n",
                "firewalld",
            ),
            ("IPT_X 1;\nFIREWD_Y 2;\n", "firewalld"),
            ("FIREWD_Y 2;\nIPT_X 1;\n", "firewalld"),
            ("PF_ANCHOR_NAME fwknop;\nFIREWD_Y 2;\n", "firewalld"),
        ] {
            assert_eq!(parse_server_config(input).firewall, Some(want), "{input}");
        }
    }

    #[test]
    fn bsd_firewalls_are_skipped_with_a_warning() {
        // fwknop-go set action_template: pf.yaml / ipfw.yaml; fwknop-rs
        // supports Linux only and ships no templates for them.
        let conv = parse_server_config(
            "UDPSERV_PORT 62201;\nPF_ANCHOR_NAME fwknop;\nIPFW_START_RULE_NUM 10000;\nIPFW_MAX_RULES 100;\n",
        );
        assert_eq!(conv.firewall, None);
        assert!(!conv.config.contains_key("action_template"));
        assert_eq!(
            conv.warnings,
            [
                "ipfw firewall configuration skipped (IPFW_START_RULE_NUM, IPFW_MAX_RULES): \
                 fwknop-rs supports Linux only; use action_template: nftables.yaml or iptables.yaml",
                "pf firewall configuration skipped (PF_ANCHOR_NAME): \
                 fwknop-rs supports Linux only; use action_template: nftables.yaml or iptables.yaml",
            ]
        );
        assert!(!render_server(&conv).contains("Detected"));
    }

    #[test]
    fn warnings() {
        let conv = parse_server_config("GPG_HOME_DIR /root/.gnupg;\nGPG_EXE /usr/bin/gpg;\n");
        assert_eq!(conv.warnings.len(), 2);
        assert!(conv.warnings.iter().all(|w| w.contains("GPG")));
        let conv = parse_server_config(
            "ENABLE_SPA_OVER_HTTP Y;\nALLOW_ANY_USER_AGENT N;\nENABLE_X_FORWARDED_FOR N;\n",
        );
        assert_eq!(conv.warnings.len(), 3);
        let conv = parse_server_config("ENABLE_EXTERNAL_CMDS Y;\nEXTERNAL_CMD_OPEN x;\n");
        assert!(conv.warnings.iter().all(|w| w.contains("action templates")));
        let conv = parse_server_config("NFQ_QUEUE_NUMBER 1;\nSOMETHING_ELSE 1;\n");
        assert_eq!(
            conv.warnings[0],
            "NFQ capture not supported; key NFQ_QUEUE_NUMBER skipped (use UDP server mode)"
        );
        assert_eq!(conv.warnings[1], "unrecognized key SOMETHING_ELSE");
    }

    #[test]
    fn run_dir_is_no_longer_converted() {
        let conv = parse_server_config("FWKNOP_RUN_DIR /var/run/fwknop;\n");
        assert!(!conv.config.contains_key("run_dir"));
        assert_eq!(
            conv.warnings,
            ["not used by fwknopd: key FWKNOP_RUN_DIR skipped"]
        );
    }

    #[test]
    fn booleans_and_comments() {
        let conv = parse_server_config(
            "# comment\n\nENABLE_DIGEST_PERSISTENCE Y;\nENABLE_SPA_PACKET_AGING N;\nVERBOSE 2;\n",
        );
        assert_eq!(conv.config["enable_digest_persistence"], Val::Bool(true));
        assert_eq!(conv.config["enable_spa_packet_aging"], Val::Bool(false));
        assert_eq!(conv.config["verbose"], Val::Bool(true));
    }

    #[test]
    fn all_valid_keys() {
        let conv = parse_server_config(
            "UDPSERV_PORT 62201;\nVERBOSE 2;\nMAX_SPA_PACKET_AGE 120;\nSYSLOG_IDENTITY fwknopd;\n\
             SYSLOG_FACILITY LOG_DAEMON;\nFWKNOP_RUN_DIR /var/run/fwknop;\n\
             FWKNOP_PID_FILE /var/run/fwknop/fwknopd.pid;\nACCESS_FILE /etc/fwknop/access.conf;\n\
             ENABLE_SPA_PACKET_AGING Y;\nENABLE_DIGEST_PERSISTENCE Y;\n",
        );
        // fwknop-go also converted FWKNOP_RUN_DIR (to run_dir, which nothing
        // read); fwknop-rs skips it with a warning.
        assert_eq!(
            conv.warnings,
            ["not used by fwknopd: key FWKNOP_RUN_DIR skipped"]
        );
        assert_eq!(conv.config.len(), 9);
    }

    #[test]
    fn render_has_header_and_sorted_keys() {
        let conv = parse_server_config(
            "UDPSERV_PORT 62201;\nIPT_X 1;\nACCESS_FILE /etc/fwknop/access.yaml;\n",
        );
        assert_eq!(
            render_server(&conv),
            "# Detected iptables firewall configuration from legacy config.\n\
             access_file: /etc/fwknop/access.yaml\naction_template: iptables.yaml\nudp_port: 62201\n"
        );
    }
}
