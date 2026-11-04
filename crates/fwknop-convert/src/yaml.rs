//! A small YAML writer for the converter's output: mappings with sorted or
//! given key order, lists of strings, and scalars quoted whenever a plain
//! scalar could be read as anything other than the intended value.

use std::fmt::Write as _;

/// A converted value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Val {
    Str(String),
    Bool(bool),
    Int(i64),
    List(Vec<String>),
}

impl Val {
    /// An integer when `s` is one, otherwise the string.
    pub fn int_or_str(s: &str) -> Val {
        s.parse()
            .map(Val::Int)
            .unwrap_or_else(|_| Val::Str(s.to_string()))
    }
}

/// Writes `entries` (already in output order) as a block mapping indented
/// by `indent` spaces. An empty mapping is written as `{}` on the key's
/// line by the caller.
pub fn write_mapping(out: &mut String, entries: &[(String, Val)], indent: usize) {
    let pad = " ".repeat(indent);
    for (key, val) in entries {
        let _ = write!(out, "{pad}{}:", scalar(key));
        match val {
            Val::Str(s) => {
                let _ = writeln!(out, " {}", scalar(s));
            }
            Val::Bool(b) => {
                let _ = writeln!(out, " {b}");
            }
            Val::Int(i) => {
                let _ = writeln!(out, " {i}");
            }
            Val::List(items) if items.is_empty() => {
                let _ = writeln!(out, " []");
            }
            Val::List(items) => {
                out.push('\n');
                for item in items {
                    let _ = writeln!(out, "{pad}  - {}", scalar(item));
                }
            }
        }
    }
}

/// A scalar written plain when that is unambiguous, otherwise
/// double-quoted.
pub fn scalar(s: &str) -> String {
    if is_plain_safe(s) {
        s.to_string()
    } else {
        quote(s)
    }
}

fn is_plain_safe(s: &str) -> bool {
    let Some(first) = s.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '/' || first == '_' || first == '.') {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./+=-@%,".contains(c))
    {
        return false;
    }
    !looks_like_non_string(s)
}

/// Words YAML 1.1 or 1.2 readers would take as booleans, null or numbers.
fn looks_like_non_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true"
            | "false"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "y"
            | "n"
            | "null"
            | "~"
            | ".inf"
            | ".nan"
            | "-.inf"
            | "+.inf"
    ) {
        return true;
    }
    let body = lower.strip_prefix(['+', '-']).unwrap_or(&lower);
    is_yaml_int(body) || is_yaml_float(body)
}

/// Decimal, `0x`, `0o` or `0b` integers, with `_` separators.
fn is_yaml_int(s: &str) -> bool {
    let (digits, radix) = if let Some(d) = s.strip_prefix("0x") {
        (d, 16)
    } else if let Some(d) = s.strip_prefix("0o") {
        (d, 8)
    } else if let Some(d) = s.strip_prefix("0b") {
        (d, 2)
    } else {
        (s, 10)
    };
    !digits.is_empty()
        && digits.chars().any(|c| c.is_digit(radix))
        && digits.chars().all(|c| c == '_' || c.is_digit(radix))
}

/// `1.5`, `.5`, `1.`, `1e5`, `1.5e-3`: one dot at most, an optional
/// exponent, and at least one digit before it.
fn is_yaml_float(s: &str) -> bool {
    let (mantissa, exponent) = match s.split_once('e') {
        Some((m, e)) => (m, Some(e)),
        None => (s, None),
    };
    let dots = mantissa.matches('.').count();
    let mantissa_ok = dots <= 1
        && mantissa.chars().any(|c| c.is_ascii_digit())
        && mantissa
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '_');
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && e.chars().all(|c| c.is_ascii_digit())
    });
    mantissa_ok && exponent_ok && (dots == 1 || exponent.is_some())
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go's `parseBool` in the converter: `Y`, `YES`, `1` and `TRUE` (any case)
/// are true; anything else is false.
pub fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_uppercase().as_str(),
        "Y" | "YES" | "1" | "TRUE"
    )
}

/// Splits a line into its key and the rest, on the first space (or the
/// first tab when there is no space), as fwknop-go does.
pub fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once(' ').or_else(|| line.split_once('\t'))?;
    Some((k.trim(), v.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        for plain in [
            "tcp/22",
            "127.0.0.1",
            "fwknopd",
            "bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=",
            "iptables.yaml",
            "/var/run/fwknop",
            "ANY",
            "192.168.1.0/24,10.0.0.1",
        ] {
            assert_eq!(scalar(plain), plain);
        }
        for (input, quoted) in [
            ("", "\"\""),
            ("Y", "\"Y\""),
            ("yes", "\"yes\""),
            ("62201", "\"62201\""),
            ("0x10", "\"0x10\""),
            ("1.5", "\"1.5\""),
            ("1e5", "\"1e5\""),
            ("-7", "\"-7\""),
            ("::1", "\"::1\""),
            ("2001:db8::1", "\"2001:db8::1\""),
            ("a b", "\"a b\""),
            ("has \"quote\"", "\"has \\\"quote\\\"\""),
            ("#comment", "\"#comment\""),
            ("- dash", "\"- dash\""),
            ("~", "\"~\""),
        ] {
            assert_eq!(scalar(input), quoted, "{input}");
        }
    }

    #[test]
    fn written_yaml_reads_back() {
        let entries = vec![
            ("a".to_string(), Val::Str("Y".into())),
            ("b".to_string(), Val::Bool(true)),
            ("c".to_string(), Val::Int(30)),
            ("e".to_string(), Val::Str("2001:db8::1".into())),
            ("f".to_string(), Val::Str("x: y # z".into())),
        ];
        let mut out = String::new();
        write_mapping(&mut out, &entries, 0);
        let raw = cli_common_yaml(&out);
        assert!(raw.contains(r#"("a", Str("Y"))"#), "{raw}");
        assert!(raw.contains(r#"("b", Bool(true))"#), "{raw}");
        assert!(raw.contains(r#"("c", Int(30))"#), "{raw}");
        assert!(raw.contains(r#"("e", Str("2001:db8::1"))"#), "{raw}");
        assert!(raw.contains(r#"("f", Str("x: y # z"))"#), "{raw}");
    }

    fn cli_common_yaml(text: &str) -> String {
        match cli_common::layers::parse_untyped_yaml(text).unwrap() {
            cli_common::layers::Raw::Map(entries) => format!("{entries:?}"),
            other => panic!("expected a mapping, got {other:?}"),
        }
    }

    #[test]
    fn bools_and_splitting() {
        for t in ["Y", "y", "YES", "1", "true", " TRUE "] {
            assert!(parse_bool(t), "{t}");
        }
        for f in ["N", "no", "0", "", "maybe"] {
            assert!(!parse_bool(f), "{f}");
        }
        assert_eq!(
            split_key_value("KEY value here"),
            Some(("KEY", "value here"))
        );
        assert_eq!(split_key_value("KEY\t\tvalue"), Some(("KEY", "value")));
        assert_eq!(split_key_value("KEYONLY"), None);
    }
}
