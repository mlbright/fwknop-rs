//! The client's YAML rc file (`~/.fwknoprc`): one rc stanza per top-level
//! key, `default` applying underneath any other.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use cli_common::layers::{Layers, Raw, parse_untyped_yaml};

/// Rc stanzas in file order.
pub type Stanzas = Vec<(String, Vec<(String, Raw)>)>;

/// Loads the `default` rc stanza and then `stanza` (unless it is empty or
/// `default`) into `layers`. A missing file is reported as
/// [`std::io::ErrorKind::NotFound`] so the caller can ignore it.
pub fn load_rc_file(layers: &mut Layers, path: &Path, stanza: &str) -> Result<()> {
    let data = std::fs::read_to_string(path)?;
    let stanzas = match parse_rc(&data) {
        Ok(s) => s,
        Err(_) if looks_like_legacy(&data) => return Err(legacy_error(path)),
        Err(e) => return Err(e),
    };
    apply_stanzas(layers, &stanzas, stanza)
}

pub fn apply_stanzas(layers: &mut Layers, stanzas: &Stanzas, stanza: &str) -> Result<()> {
    if let Some((_, values)) = stanzas.iter().find(|(name, _)| name == "default") {
        layers.load_map(values.clone());
    }
    if !stanza.is_empty() && stanza != "default" {
        let (_, values) = stanzas
            .iter()
            .find(|(name, _)| name == stanza)
            .ok_or_else(|| anyhow!("stanza {stanza:?} not found in rc file"))?;
        layers.load_map(values.clone());
    }
    Ok(())
}

/// Parses a YAML rc file into rc stanzas.
pub fn parse_rc(data: &str) -> Result<Stanzas> {
    let raw = parse_untyped_yaml(data).map_err(|e| anyhow!("parsing YAML rc file: {e}"))?;
    let entries = match raw {
        Raw::Null => return Ok(Vec::new()),
        Raw::Map(entries) => entries,
        _ => bail!("parsing YAML rc file: expected a mapping of rc stanzas"),
    };
    entries
        .into_iter()
        .map(|(name, body)| match body {
            Raw::Map(values) => Ok((name, values)),
            Raw::Null => Ok((name, Vec::new())),
            _ => Err(anyhow!(
                "parsing YAML rc file: rc stanza {name:?} must be a mapping"
            )),
        })
        .collect()
}

/// Whether the file looks like a legacy C fwknop INI rc file: its first
/// line that is not blank or a comment starts with `[`.
pub fn looks_like_legacy(data: &str) -> bool {
    data.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .is_some_and(|l| l.starts_with('['))
}

fn legacy_error(path: &Path) -> anyhow::Error {
    anyhow!(
        "legacy .fwknoprc format is no longer supported; convert with: fwknop-convert --type client --input {}",
        path.display()
    )
}

/// The names of the rc stanzas in the file, in file order.
pub fn list_stanzas(path: &Path) -> Result<Vec<String>> {
    let data = std::fs::read_to_string(path).with_context(|| format!("open {}", path.display()))?;
    if looks_like_legacy(&data) {
        return Err(legacy_error(path));
    }
    let raw = parse_untyped_yaml(&data).map_err(|e| anyhow!(e))?;
    match raw {
        Raw::Null => Ok(Vec::new()),
        Raw::Map(entries) => Ok(entries.into_iter().map(|(name, _)| name).collect()),
        _ => bail!("expected a mapping of rc stanzas"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const RC: &str = "\
default:
  destination: 192.168.1.100
  access: tcp/22
  key_base64: dGVzdGtleQ==
production:
  destination: prod.example.com
  access: tcp/22
staging:
  destination: staging.example.com
  server_port: 12345
";

    fn load(stanza: &str) -> Result<Layers> {
        let mut l = Layers::new();
        apply_stanzas(&mut l, &parse_rc(RC)?, stanza)?;
        Ok(l)
    }

    #[test]
    fn default_stanza() {
        let l = load("").unwrap();
        assert_eq!(l.string("destination").unwrap(), "192.168.1.100");
        assert_eq!(l.string("key_base64").unwrap(), "dGVzdGtleQ==");
    }

    #[test]
    fn named_stanza_overlays_default() {
        let l = load("staging").unwrap();
        assert_eq!(l.string("destination").unwrap(), "staging.example.com");
        assert_eq!(l.int("server_port").unwrap(), 12345);
        assert_eq!(l.string("access").unwrap(), "tcp/22");
        assert_eq!(l.string("key_base64").unwrap(), "dGVzdGtleQ==");
    }

    #[test]
    fn missing_stanza_is_an_error() {
        let err = load("nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn file_round_trip_and_missing_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(RC.as_bytes()).unwrap();
        let mut l = Layers::new();
        load_rc_file(&mut l, f.path(), "production").unwrap();
        assert_eq!(l.string("destination").unwrap(), "prod.example.com");

        let err = load_rc_file(&mut l, Path::new("/nonexistent/fwknoprc"), "").unwrap_err();
        let io = err.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn legacy_format_gets_a_conversion_hint() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"[default]\nSPA_SERVER  192.168.1.1\nACCESS  tcp/22\n")
            .unwrap();
        let err = load_rc_file(&mut Layers::new(), f.path(), "").unwrap_err();
        assert!(err.to_string().contains("fwknop-convert"), "{err:#}");
        let err = list_stanzas(f.path()).unwrap_err();
        assert!(err.to_string().contains("fwknop-convert"), "{err}");
    }

    #[test]
    fn legacy_detection() {
        assert!(looks_like_legacy("[default]\nkey value\n"));
        assert!(looks_like_legacy("# comment\n; another\n\n  [server]\n"));
        assert!(!looks_like_legacy("default:\n  key: value\n"));
        assert!(!looks_like_legacy(""));
        assert!(!looks_like_legacy("# only comments\n"));
    }

    #[test]
    fn stanzas_are_listed_in_file_order() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(RC.as_bytes()).unwrap();
        assert_eq!(
            list_stanzas(f.path()).unwrap(),
            ["default", "production", "staging"]
        );
    }
}

#[cfg(test)]
mod sample_tests {
    use super::*;

    #[test]
    fn sample_client_configs_load() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for rel in [
            "examples/configs/client-basic.yaml",
            "examples/configs/client-nat.yaml",
        ] {
            let text = std::fs::read_to_string(root.join(rel)).unwrap();
            let stanzas = parse_rc(&text).unwrap_or_else(|e| panic!("{rel}: {e:#}"));
            assert!(!stanzas.is_empty(), "{rel}");
            for (name, _) in &stanzas {
                let mut layers = Layers::new();
                apply_stanzas(&mut layers, &stanzas, name).unwrap();
                assert!(
                    !layers.string("destination").unwrap().is_empty(),
                    "{rel} [{name}]"
                );
            }
        }
    }
}
