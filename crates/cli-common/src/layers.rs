//! Layered configuration with fwknop-go's precedence and loose typing.
//!
//! fwknop-go merges config with koanf: each layer overwrites keys set by the
//! one before, and the result is decoded with mapstructure's
//! `WeaklyTypedInput`, so `"62201"` is accepted for an int, `1` for a bool,
//! `true` for a string (as `"1"`), and so on. [`Layers`] reproduces both.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};

/// One untyped config value, as YAML, an environment variable or a flag
/// produced it.
#[derive(Debug, Clone, PartialEq)]
pub enum Raw {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// A nested mapping, in document order. Flattened into dotted keys when
    /// loaded into [`Layers`].
    Map(Vec<(String, Raw)>),
}

impl Raw {
    /// Converts like mapstructure's weak string decoding.
    pub fn to_go_string(&self, key: &str) -> Result<String, String> {
        Ok(match self {
            Raw::Null => String::new(),
            Raw::Bool(b) => if *b { "1" } else { "0" }.to_string(),
            Raw::Int(i) => i.to_string(),
            Raw::Float(f) => format_go_float(*f),
            Raw::Str(s) => s.clone(),
            Raw::Map(_) => return Err(format!("'{key}' expected a string, got a mapping")),
        })
    }

    /// Converts like mapstructure's weak int decoding.
    pub fn to_go_int(&self, key: &str) -> Result<i64, String> {
        match self {
            Raw::Null => Ok(0),
            Raw::Bool(b) => Ok(i64::from(*b)),
            Raw::Int(i) => Ok(*i),
            Raw::Float(f) => Ok(f.trunc() as i64),
            Raw::Str(s) if s.is_empty() => Ok(0),
            Raw::Str(s) => parse_go_int(s).map_err(|e| format!("cannot parse '{key}' as int: {e}")),
            Raw::Map(_) => Err(format!("'{key}' expected an int, got a mapping")),
        }
    }

    /// Converts like mapstructure's weak bool decoding.
    pub fn to_go_bool(&self, key: &str) -> Result<bool, String> {
        match self {
            Raw::Null => Ok(false),
            Raw::Bool(b) => Ok(*b),
            Raw::Int(i) => Ok(*i != 0),
            Raw::Float(f) => Ok(*f != 0.0),
            Raw::Str(s) if s.is_empty() => Ok(false),
            Raw::Str(s) => {
                parse_go_bool(s).map_err(|e| format!("cannot parse '{key}' as bool: {e}"))
            }
            Raw::Map(_) => Err(format!("'{key}' expected a bool, got a mapping")),
        }
    }
}

/// Formats like Go's `strconv.FormatFloat(f, 'f', -1, 64)`.
fn format_go_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "+Inf" } else { "-Inf" }.into();
    }
    // Rust's Display already prints the shortest representation that
    // round-trips, without an exponent.
    let s = f.to_string();
    if s == "-0" { "-0".into() } else { s }
}

/// Parses like Go's `strconv.ParseBool`.
pub fn parse_go_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("strconv.ParseBool: parsing {s:?}: invalid syntax")),
    }
}

/// Parses like Go's `strconv.ParseInt(s, 0, 64)`: optional sign, then a
/// `0x`, `0o`, `0b` or `0` (octal) prefix, with `_` allowed between digits.
pub fn parse_go_int(s: &str) -> Result<i64, String> {
    let err = || format!("strconv.ParseInt: parsing {s:?}: invalid syntax");
    let (neg, body) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let lower = body.to_ascii_lowercase();
    let (radix, digits, prefixed) = if let Some(d) = lower.strip_prefix("0x") {
        (16, d, true)
    } else if let Some(d) = lower.strip_prefix("0o") {
        (8, d, true)
    } else if let Some(d) = lower.strip_prefix("0b") {
        (2, d, true)
    } else if lower.len() > 1 && lower.starts_with('0') {
        (8, &lower[1..], true)
    } else {
        (10, lower.as_str(), false)
    };
    // Underscores may only separate digits (or follow a base prefix).
    let bytes = digits.as_bytes();
    if digits.is_empty()
        || bytes.last() == Some(&b'_')
        || (!prefixed && bytes.first() == Some(&b'_'))
        || digits.contains("__")
    {
        return Err(err());
    }
    let clean: String = digits.chars().filter(|&c| c != '_').collect();
    if clean.is_empty() {
        return Err(err());
    }
    let magnitude = u64::from_str_radix(&clean, radix).map_err(|_| err())?;
    if neg {
        if magnitude > i64::MAX as u64 + 1 {
            return Err(format!(
                "strconv.ParseInt: parsing {s:?}: value out of range"
            ));
        }
        Ok((magnitude as i64).wrapping_neg())
    } else {
        i64::try_from(magnitude)
            .map_err(|_| format!("strconv.ParseInt: parsing {s:?}: value out of range"))
    }
}

impl<'de> Deserialize<'de> for Raw {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Raw, D::Error> {
        d.deserialize_any(RawVisitor)
    }
}

struct RawVisitor;

impl<'de> Visitor<'de> for RawVisitor {
    type Value = Raw;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a scalar or a mapping")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Raw, E> {
        Ok(Raw::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Raw, E> {
        Ok(Raw::Int(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Raw, E> {
        i64::try_from(v)
            .map(Raw::Int)
            .map_err(|_| E::custom(format!("integer {v} out of range")))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Raw, E> {
        Ok(Raw::Float(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Raw, E> {
        Ok(Raw::Str(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Raw, E> {
        Ok(Raw::Str(v))
    }
    fn visit_unit<E>(self) -> Result<Raw, E> {
        Ok(Raw::Null)
    }
    fn visit_none<E>(self) -> Result<Raw, E> {
        Ok(Raw::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Raw, D::Error> {
        Raw::deserialize(d)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
        let mut entries = Vec::new();
        while let Some((k, v)) = map.next_entry::<RawKey, Raw>()? {
            entries.push((k.0, v));
        }
        Ok(Raw::Map(entries))
    }
}

/// A mapping key; YAML allows scalars of any type, and Go stringifies them.
struct RawKey(String);

impl<'de> Deserialize<'de> for RawKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<RawKey, D::Error> {
        let raw = Raw::deserialize(d)?;
        raw.to_go_string("key")
            .map(RawKey)
            .map_err(de::Error::custom)
    }
}

/// A YAML document read the way fwknop-go reads `server.yaml` and
/// `~/.fwknoprc`: into untyped values, where only `true`/`false` are
/// booleans (YAML 1.2), so `yes` stays the string `"yes"`.
pub fn parse_untyped_yaml(text: &str) -> Result<Raw, String> {
    if text.trim().is_empty() || is_only_comments(text) {
        return Ok(Raw::Null);
    }
    let options = serde_saphyr::options! {
        strict_booleans: true,
    };
    serde_saphyr::from_str_with_options::<Raw>(text, options).map_err(|e| e.to_string())
}

fn is_only_comments(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .all(|l| l.is_empty() || l.starts_with('#') || l == "---" || l == "...")
}

/// Merged configuration: later [`set`](Layers::set) calls win, keys are
/// matched case-insensitively (as mapstructure does), and missing keys read
/// as zero values.
#[derive(Debug, Clone, Default)]
pub struct Layers {
    values: BTreeMap<String, Raw>,
}

impl Layers {
    pub fn new() -> Layers {
        Layers::default()
    }

    /// Sets `key`, overriding any earlier layer. A [`Raw::Map`] is
    /// flattened into `key.subkey` entries.
    pub fn set(&mut self, key: &str, value: Raw) {
        let key = key.to_ascii_lowercase();
        match value {
            Raw::Map(entries) => {
                for (k, v) in entries {
                    self.set(&format!("{key}.{k}"), v);
                }
            }
            v => {
                self.values.insert(key, v);
            }
        }
    }

    /// Sets `key` only if no layer has set it yet (how unchanged flag
    /// defaults are applied).
    pub fn set_default(&mut self, key: &str, value: Raw) {
        if self.get(key).is_none() {
            self.set(key, value);
        }
    }

    /// Loads a whole YAML mapping (`server.yaml`, an rc stanza) as a layer.
    pub fn load_map(&mut self, entries: Vec<(String, Raw)>) {
        for (k, v) in entries {
            self.set(&k, v);
        }
    }

    /// Loads every environment variable starting with `prefix`, with the
    /// prefix removed and the rest lower-cased (`FWKNOP_SERVER_PORT` →
    /// `server_port`).
    pub fn load_env(&mut self, prefix: &str) {
        self.load_env_from(prefix, std::env::vars_os());
    }

    pub fn load_env_from<I, K, V>(&mut self, prefix: &str, vars: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<std::ffi::OsStr>,
        V: AsRef<std::ffi::OsStr>,
    {
        for (k, v) in vars {
            let (Some(k), Some(v)) = (k.as_ref().to_str(), v.as_ref().to_str()) else {
                continue;
            };
            if let Some(key) = k.strip_prefix(prefix)
                && !key.is_empty()
            {
                self.set(key, Raw::Str(v.to_string()));
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&Raw> {
        self.values.get(&key.to_ascii_lowercase())
    }

    /// Whether `key` or any `key.subkey` is set.
    pub fn contains_prefix(&self, key: &str) -> bool {
        let key = key.to_ascii_lowercase();
        let dotted = format!("{key}.");
        self.values
            .keys()
            .any(|k| *k == key || k.starts_with(&dotted))
    }

    pub fn string(&self, key: &str) -> Result<String, String> {
        self.get(key)
            .map_or(Ok(String::new()), |v| v.to_go_string(key))
    }

    pub fn int(&self, key: &str) -> Result<i64, String> {
        self.get(key).map_or(Ok(0), |v| v.to_go_int(key))
    }

    pub fn bool(&self, key: &str) -> Result<bool, String> {
        self.get(key).map_or(Ok(false), |v| v.to_go_bool(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_layers_win_and_defaults_fill_gaps() {
        let mut l = Layers::new();
        l.set("destination", Raw::Str("rc.example".into()));
        l.set("DESTINATION", Raw::Str("env.example".into()));
        l.set_default("destination", Raw::Str("default".into()));
        l.set_default("server_port", Raw::Int(62201));
        assert_eq!(l.string("destination").unwrap(), "env.example");
        assert_eq!(l.int("server_port").unwrap(), 62201);
        assert_eq!(l.string("missing").unwrap(), "");
        assert!(!l.bool("missing").unwrap());
    }

    #[test]
    fn weak_conversions_match_mapstructure() {
        assert_eq!(Raw::Str("62201".into()).to_go_int("k").unwrap(), 62201);
        assert_eq!(Raw::Str("0x10".into()).to_go_int("k").unwrap(), 16);
        assert_eq!(Raw::Str("010".into()).to_go_int("k").unwrap(), 8);
        assert_eq!(Raw::Str("1_000".into()).to_go_int("k").unwrap(), 1000);
        assert_eq!(Raw::Str("".into()).to_go_int("k").unwrap(), 0);
        assert_eq!(Raw::Bool(true).to_go_int("k").unwrap(), 1);
        assert_eq!(Raw::Float(2.9).to_go_int("k").unwrap(), 2);
        assert!(Raw::Str("abc".into()).to_go_int("k").is_err());

        assert!(Raw::Str("true".into()).to_go_bool("k").unwrap());
        assert!(Raw::Str("T".into()).to_go_bool("k").unwrap());
        assert!(!Raw::Str("0".into()).to_go_bool("k").unwrap());
        assert!(Raw::Int(2).to_go_bool("k").unwrap());
        assert!(Raw::Str("yes".into()).to_go_bool("k").is_err());

        assert_eq!(Raw::Bool(true).to_go_string("k").unwrap(), "1");
        assert_eq!(Raw::Int(22).to_go_string("k").unwrap(), "22");
        assert_eq!(Raw::Float(1.5).to_go_string("k").unwrap(), "1.5");
        assert_eq!(Raw::Null.to_go_string("k").unwrap(), "");
    }

    #[test]
    fn go_int_parsing() {
        for (s, want) in [
            ("0", 0),
            ("-5", -5),
            ("+7", 7),
            ("0b101", 5),
            ("0o17", 15),
            ("0X1f", 31),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
        ] {
            assert_eq!(parse_go_int(s), Ok(want), "{s}");
        }
        for s in [
            "",
            "-",
            "0x",
            "1_",
            "_1",
            "1__0",
            "09",
            "1.5",
            " 1",
            "9223372036854775808",
        ] {
            assert!(parse_go_int(s).is_err(), "{s}");
        }
    }

    #[test]
    fn env_vars_are_prefixed_and_lowercased() {
        let mut l = Layers::new();
        l.load_env_from(
            "FWKNOP_",
            [
                ("FWKNOP_SERVER_PORT", "1234"),
                ("FWKNOP_HMAC_KEY_BASE64", "abc"),
                ("FWKNOPD_UDP_PORT", "9"),
                ("PATH", "/bin"),
                ("FWKNOP_", "ignored"),
            ],
        );
        assert_eq!(l.int("server_port").unwrap(), 1234);
        assert_eq!(l.string("hmac_key_base64").unwrap(), "abc");
        assert!(l.get("d_udp_port").is_none());
        assert!(l.get("path").is_none());
    }

    #[test]
    fn untyped_yaml_keeps_yaml_1_1_words_as_strings() {
        let raw = parse_untyped_yaml(
            "a: yes\nb: true\nc: 22\nd: \"22\"\ne: 1.5\nf:\ng: on\nnested:\n  x: 1\n",
        )
        .unwrap();
        let Raw::Map(entries) = raw else {
            panic!("expected a mapping")
        };
        let get = |k: &str| entries.iter().find(|(key, _)| key == k).unwrap().1.clone();
        assert_eq!(get("a"), Raw::Str("yes".into()));
        assert_eq!(get("b"), Raw::Bool(true));
        assert_eq!(get("c"), Raw::Int(22));
        assert_eq!(get("d"), Raw::Str("22".into()));
        assert_eq!(get("e"), Raw::Float(1.5));
        assert_eq!(get("f"), Raw::Null);
        assert_eq!(get("g"), Raw::Str("on".into()));
        assert_eq!(get("nested"), Raw::Map(vec![("x".into(), Raw::Int(1))]));

        let mut l = Layers::new();
        l.set("actions", get("nested"));
        assert_eq!(l.int("actions.x").unwrap(), 1);
        assert!(l.contains_prefix("actions"));
    }

    #[test]
    fn untyped_yaml_preserves_order_and_handles_empty() {
        let Raw::Map(entries) = parse_untyped_yaml("zeta: 1\nalpha: 2\nmid: 3\n").unwrap() else {
            panic!()
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["zeta", "alpha", "mid"]);
        assert_eq!(parse_untyped_yaml("").unwrap(), Raw::Null);
        assert_eq!(parse_untyped_yaml("# only a comment\n").unwrap(), Raw::Null);
        assert!(parse_untyped_yaml("a: [1, 2").is_err());
    }
}
