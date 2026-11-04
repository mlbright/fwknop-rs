//! The client's configuration, merged like fwknop-go merges it (lowest
//! priority first): flag defaults, the rc file's `default` rc stanza, the
//! rc stanza named with `-n`, `FWKNOP_*` environment variables, and the flags
//! given on the command line.

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

use cli_common::layers::{Layers, Raw};
use fkospa::EncryptionKey;
use zeroize::Zeroizing;

use crate::cli::Cli;
use crate::rcfile;
use crate::resolve::DEFAULT_RESOLVE_URL;

pub const DEFAULT_SERVER_PORT: i64 = 62201;

/// Everything the client needs, after merging all layers.
#[derive(Debug, Default, Clone)]
pub struct ClientConfig {
    pub destination: String,
    pub server_port: i64,
    pub allow_ip: String,
    pub access: String,
    pub server_cmd: String,
    pub spoof_user: String,
    pub source_ip: bool,
    pub fw_timeout: i64,
    pub nat_access: String,
    pub nat_local: bool,
    pub digest_type: String,
    pub hmac_digest_type: String,
    pub encryption_mode: String,
    pub key: String,
    pub key_base64: String,
    pub key_hmac: String,
    pub hmac_key_base64: String,
    pub use_hmac: bool,
    pub resolve_ip: bool,
    pub resolve_url: String,
    pub time_offset_plus: String,
    pub time_offset_minus: String,
    pub rc_file: String,
    pub test: bool,
    pub verbose: i64,
    pub key_gen: bool,
    pub stanza_list: bool,
    pub show_version: bool,
}

/// Merges the rc file, the environment (`env`, normally
/// `std::env::vars_os()`) and the parsed flags.
pub fn load_config<I, K, V>(cli: &Cli, env: I) -> Result<ClientConfig>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    // Informational flags need no config.
    let show_version = cli.version.unwrap_or(false);
    let key_gen = cli.key_gen.unwrap_or(false);
    if show_version || key_gen {
        return Ok(ClientConfig {
            show_version,
            key_gen,
            ..ClientConfig::default()
        });
    }

    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = env
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
        .collect();
    let mut layers = Layers::new();

    // 1. The rc file (lowest priority). Which file and rc stanza come from
    //    the flags alone, as in fwknop-go.
    if !cli.no_rc_file.unwrap_or(false) {
        let rc_path = match &cli.rc_file {
            Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
            _ => default_rc_path(&env),
        };
        if let Some(path) = rc_path {
            let stanza = cli.named_config.as_deref().unwrap_or("");
            if let Err(e) = rcfile::load_rc_file(&mut layers, &path, stanza) {
                let not_found = e
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == ErrorKind::NotFound);
                if !not_found {
                    return Err(e.context("loading rc file"));
                }
            }
        }
    }

    // 2. Environment variables.
    layers.load_env_from("FWKNOP_", env);

    // 3. Flags that were given, then defaults for the ones that were not.
    apply_flags(&mut layers, cli);

    from_layers(&layers).map_err(|e| anyhow!("unmarshalling config: {e}"))
}

/// `~/.fwknoprc`, using `$HOME` like Go's `os.UserHomeDir`.
pub fn default_rc_path(env: &[(std::ffi::OsString, std::ffi::OsString)]) -> Option<PathBuf> {
    env.iter()
        .find(|(k, _)| k == "HOME")
        .map(|(_, v)| PathBuf::from(v))
        .filter(|p| !p.as_os_str().is_empty())
        .map(|home| home.join(".fwknoprc"))
}

fn apply_flags(layers: &mut Layers, cli: &Cli) {
    let mut s = |key: &str, v: &Option<String>| {
        if let Some(v) = v {
            layers.set(key, Raw::Str(v.clone()));
        }
    };
    s("destination", &cli.destination);
    s("allow_ip", &cli.allow_ip);
    s("access", &cli.access);
    s("server_cmd", &cli.server_cmd);
    s("spoof_user", &cli.spoof_user);
    s("nat_access", &cli.nat_access);
    s("digest_type", &cli.digest_type);
    s("hmac_digest_type", &cli.hmac_digest_type);
    s("encryption_mode", &cli.encryption_mode);
    s("key", &cli.key);
    s("key_base64", &cli.key_base64);
    s("key_hmac", &cli.key_hmac);
    // The flag is --key-base64-hmac but the config key is hmac_key_base64.
    s("hmac_key_base64", &cli.key_base64_hmac);
    s("resolve_url", &cli.resolve_url);
    s("time_offset_plus", &cli.time_offset_plus);
    s("time_offset_minus", &cli.time_offset_minus);
    s("named_config", &cli.named_config);
    s("rc_file", &cli.rc_file);

    let mut b = |key: &str, v: Option<bool>| {
        if let Some(v) = v {
            layers.set(key, Raw::Bool(v));
        }
    };
    b("source_ip", cli.source_ip);
    b("nat_local", cli.nat_local);
    b("use_hmac", cli.use_hmac);
    b("resolve_ip", cli.resolve_ip);
    b("no_rc_file", cli.no_rc_file);
    b("stanza_list", cli.stanza_list);
    b("test", cli.test);

    if let Some(v) = cli.server_port {
        layers.set("server_port", Raw::Int(v));
    }
    if let Some(v) = cli.fw_timeout {
        layers.set("fw_timeout", Raw::Int(v));
    }
    if cli.verbose > 0 {
        layers.set("verbose", Raw::Int(i64::from(cli.verbose)));
    }

    // Flag defaults sit underneath everything else.
    layers.set_default("server_port", Raw::Int(DEFAULT_SERVER_PORT));
    layers.set_default("digest_type", Raw::Str("sha256".into()));
    layers.set_default("hmac_digest_type", Raw::Str("sha256".into()));
    layers.set_default("encryption_mode", Raw::Str("cbc".into()));
    layers.set_default("use_hmac", Raw::Bool(true));
    layers.set_default("resolve_url", Raw::Str(DEFAULT_RESOLVE_URL.into()));
}

fn from_layers(l: &Layers) -> Result<ClientConfig, String> {
    Ok(ClientConfig {
        destination: l.string("destination")?,
        server_port: l.int("server_port")?,
        allow_ip: l.string("allow_ip")?,
        access: l.string("access")?,
        server_cmd: l.string("server_cmd")?,
        spoof_user: l.string("spoof_user")?,
        source_ip: l.bool("source_ip")?,
        fw_timeout: l.int("fw_timeout")?,
        nat_access: l.string("nat_access")?,
        nat_local: l.bool("nat_local")?,
        digest_type: l.string("digest_type")?,
        hmac_digest_type: l.string("hmac_digest_type")?,
        encryption_mode: l.string("encryption_mode")?,
        key: l.string("key")?,
        key_base64: l.string("key_base64")?,
        key_hmac: l.string("key_hmac")?,
        hmac_key_base64: l.string("hmac_key_base64")?,
        use_hmac: l.bool("use_hmac")?,
        resolve_ip: l.bool("resolve_ip")?,
        resolve_url: l.string("resolve_url")?,
        time_offset_plus: l.string("time_offset_plus")?,
        time_offset_minus: l.string("time_offset_minus")?,
        rc_file: l.string("rc_file")?,
        test: l.bool("test")?,
        verbose: l.int("verbose")?,
        key_gen: l.bool("key_gen")?,
        stanza_list: l.bool("stanza_list")?,
        show_version: l.bool("version")?,
    })
}

impl ClientConfig {
    /// The encryption key: `key_base64` if set, else `key`.
    pub fn encryption_key(&self) -> Result<EncryptionKey> {
        if !self.key_base64.is_empty() {
            return EncryptionKey::from_base64(&self.key_base64).context("key_base64");
        }
        if !self.key.is_empty() {
            return Ok(EncryptionKey::new(self.key.as_bytes()));
        }
        bail!("no encryption key specified (use --key or --key-base64)")
    }

    /// The HMAC key bytes, or `None` when HMAC is disabled:
    /// `hmac_key_base64` if set, else `key_hmac`.
    pub fn hmac_key_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if !self.use_hmac {
            return Ok(None);
        }
        if !self.hmac_key_base64.is_empty() {
            return fkospa::decode_base64_key(&self.hmac_key_base64)
                .map(|k| Some(Zeroizing::new(k)))
                .context("hmac_key_base64");
        }
        if !self.key_hmac.is_empty() {
            return Ok(Some(Zeroizing::new(self.key_hmac.as_bytes().to_vec())));
        }
        bail!("no HMAC key specified (use --key-hmac or --key-base64-hmac)")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use clap::Parser;
    use fkospa::{DigestType, EncryptionMode, HmacType};

    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("fwknop").chain(args.iter().copied())).unwrap()
    }

    fn load(args: &[&str], env: &[(&str, &str)]) -> ClientConfig {
        load_config(&cli(args), env.iter().copied()).unwrap()
    }

    #[test]
    fn digest_hmac_and_mode_names() {
        for (name, want) in [
            ("md5", DigestType::Md5),
            ("sha3_256", DigestType::Sha3_256),
            ("sha3-512", DigestType::Sha3_512),
            ("SHA256", DigestType::Sha256),
            ("Sha512", DigestType::Sha512),
        ] {
            assert_eq!(name.parse::<DigestType>().unwrap(), want);
        }
        assert!("bogus".parse::<DigestType>().is_err());
        assert!("".parse::<DigestType>().is_err());
        assert!("invalid".parse::<HmacType>().is_err());
        assert_eq!(
            "LEGACY".parse::<EncryptionMode>().unwrap(),
            EncryptionMode::CbcLegacyIv
        );
        assert!("ecb".parse::<EncryptionMode>().is_err());
    }

    #[test]
    fn encryption_key_sources() {
        let c = |key_base64: &str, key: &str| ClientConfig {
            key_base64: key_base64.into(),
            key: key.into(),
            ..ClientConfig::default()
        };
        assert_eq!(c("dGVzdGtleQ==", "").encryption_key().unwrap().len(), 7);
        assert_eq!(c("", "mypassword").encryption_key().unwrap().len(), 10);
        assert_eq!(
            c("dGVzdGtleQ==", "other").encryption_key().unwrap().len(),
            7
        );
        assert!(c("", "").encryption_key().is_err());
        assert!(c("not base64!", "").encryption_key().is_err());
    }

    #[test]
    fn hmac_key_sources() {
        let c = |use_hmac, b64: &str, plain: &str| ClientConfig {
            use_hmac,
            hmac_key_base64: b64.into(),
            key_hmac: plain.into(),
            ..ClientConfig::default()
        };
        assert!(c(false, "", "").hmac_key_bytes().unwrap().is_none());
        assert_eq!(
            c(true, "aG1hY2tleQ==", "")
                .hmac_key_bytes()
                .unwrap()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(
            c(true, "", "hmackey")
                .hmac_key_bytes()
                .unwrap()
                .unwrap()
                .len(),
            7
        );
        assert!(c(true, "", "").hmac_key_bytes().is_err());
    }

    #[test]
    fn key_base64_hmac_flag_sets_hmac_key_base64() {
        let cfg = load(&["--key-base64-hmac", "aG1hY2tleQ==", "--no-rc-file"], &[]);
        assert_eq!(cfg.hmac_key_base64, "aG1hY2tleQ==");
    }

    #[test]
    fn defaults() {
        let cfg = load(&["--no-rc-file"], &[]);
        assert_eq!(cfg.server_port, 62201);
        assert_eq!(cfg.digest_type, "sha256");
        assert_eq!(cfg.hmac_digest_type, "sha256");
        assert_eq!(cfg.encryption_mode, "cbc");
        assert!(cfg.use_hmac);
        assert_eq!(cfg.resolve_url, "https://api.ipify.org");
        assert_eq!(cfg.verbose, 0);
    }

    #[test]
    fn precedence_rc_then_env_then_flags() {
        let mut rc = tempfile::NamedTempFile::new().unwrap();
        write!(
            rc,
            "default:\n  destination: rc.example\n  server_port: 1111\n  access: tcp/22\n  use_hmac: false\nwork:\n  destination: work.example\n"
        )
        .unwrap();
        let path = rc.path().to_str().unwrap();

        let cfg = load(&["--rc-file", path], &[]);
        assert_eq!(cfg.destination, "rc.example");
        assert_eq!(cfg.server_port, 1111);
        assert!(!cfg.use_hmac, "rc file beats the flag default");

        let cfg = load(&["--rc-file", path, "-n", "work"], &[]);
        assert_eq!(cfg.destination, "work.example");
        assert_eq!(cfg.access, "tcp/22");

        let env = [
            ("FWKNOP_DESTINATION", "env.example"),
            ("FWKNOP_SERVER_PORT", "2222"),
            ("FWKNOP_USE_HMAC", "true"),
        ];
        let cfg = load(&["--rc-file", path, "-n", "work"], &env);
        assert_eq!(cfg.destination, "env.example");
        assert_eq!(cfg.server_port, 2222);
        assert!(cfg.use_hmac);

        let cfg = load(
            &[
                "--rc-file",
                path,
                "-D",
                "flag.example",
                "-p",
                "0x10",
                "--use-hmac=false",
            ],
            &env,
        );
        assert_eq!(cfg.destination, "flag.example");
        assert_eq!(cfg.server_port, 16);
        assert!(!cfg.use_hmac);
    }

    #[test]
    fn rc_file_location_comes_from_home() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join(".fwknoprc"),
            "default:\n  destination: home.example\n",
        )
        .unwrap();
        let env = [("HOME", home.path().to_str().unwrap())];
        assert_eq!(load(&[], &env).destination, "home.example");
        assert_eq!(load(&["--no-rc-file"], &env).destination, "");
        // A missing rc file is not an error.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            load(&[], &[("HOME", empty.path().to_str().unwrap())]).destination,
            ""
        );
    }

    #[test]
    fn bad_rc_file_is_an_error() {
        let mut rc = tempfile::NamedTempFile::new().unwrap();
        writeln!(rc, "default: [unclosed").unwrap();
        let err = load_config(
            &cli(&["--rc-file", rc.path().to_str().unwrap()]),
            [("", ""); 0],
        )
        .unwrap_err();
        assert!(format!("{err:#}").starts_with("loading rc file"), "{err:#}");
    }

    #[test]
    fn bad_env_value_is_an_error() {
        let err =
            load_config(&cli(&["--no-rc-file"]), [("FWKNOP_SERVER_PORT", "abc")]).unwrap_err();
        assert!(err.to_string().contains("server_port"), "{err}");
    }

    #[test]
    fn verbose_counts_and_bool_flags() {
        let cfg = load(&["--no-rc-file", "-vv", "-s", "-T", "--nat-local"], &[]);
        assert_eq!(cfg.verbose, 2);
        assert!(cfg.source_ip && cfg.test && cfg.nat_local);
        let cfg = load(&["--no-rc-file", "--test=false", "-v"], &[]);
        assert!(!cfg.test);
        assert_eq!(cfg.verbose, 1);
    }

    #[test]
    fn removed_flags_are_rejected() {
        for flag in ["--nat-port=22", "--save-rc-stanza"] {
            assert!(Cli::try_parse_from(["fwknop", flag]).is_err(), "{flag}");
        }
    }

    #[test]
    fn stray_arguments_are_ignored() {
        let cfg = load(&["--no-rc-file", "extra", "-D", "h"], &[]);
        assert_eq!(cfg.destination, "h");
    }
}
