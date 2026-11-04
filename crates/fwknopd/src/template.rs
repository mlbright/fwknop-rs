//! Actions with `{{.Name}}` placeholders (see ADR 0001).
//!
//! Only plain placeholders are supported, with optional spaces inside the
//! braces. Anything else between `{{` and `}}`, or an unknown name, is
//! rejected when the template is parsed, so a typo stops the server at
//! startup rather than when a packet arrives.

use std::fmt::Write as _;

/// The values placeholders are filled from. `source_ip`, `proto` and `port`
/// come from a parsed access message and are shell-inert; the other
/// strings are chosen by the client and are inserted single-quoted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateContext {
    /// The allow IP, or the packet source when the client sent
    /// `0.0.0.0` / `::`.
    pub source_ip: String,
    pub proto: String,
    pub port: String,
    pub username: String,
    pub timestamp: i64,
    /// The rule's timeout in seconds.
    pub timeout: i64,
    pub access_msg: String,
    pub nat_access: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placeholder {
    SourceIp,
    Proto,
    Port,
    Username,
    Timestamp,
    Timeout,
    AccessMsg,
    NatAccess,
}

const NAMES: [(&str, Placeholder); 8] = [
    ("SourceIP", Placeholder::SourceIp),
    ("Proto", Placeholder::Proto),
    ("Port", Placeholder::Port),
    ("Username", Placeholder::Username),
    ("Timestamp", Placeholder::Timestamp),
    ("Timeout", Placeholder::Timeout),
    ("AccessMsg", Placeholder::AccessMsg),
    ("NATAccess", Placeholder::NatAccess),
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Value(Placeholder),
}

/// A parsed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pieces: Vec<Piece>,
}

impl Template {
    pub fn parse(text: &str) -> Result<Template, String> {
        let mut pieces = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("{{") {
            if start > 0 {
                pieces.push(Piece::Text(rest[..start].to_string()));
            }
            let after = &rest[start + 2..];
            let end = after
                .find("}}")
                .ok_or_else(|| format!("unclosed placeholder starting at {:?}", &rest[start..]))?;
            let inner = after[..end].trim();
            let name = inner.strip_prefix('.').unwrap_or("");
            let placeholder = NAMES
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, p)| *p)
                .ok_or_else(|| {
                    let known: Vec<String> =
                        NAMES.iter().map(|(n, _)| format!("{{{{.{n}}}}}")).collect();
                    format!(
                        "unsupported placeholder {{{{{}}}}}; use one of {}",
                        &after[..end],
                        known.join(", ")
                    )
                })?;
            pieces.push(Piece::Value(placeholder));
            rest = &after[end + 2..];
        }
        if !rest.is_empty() {
            pieces.push(Piece::Text(rest.to_string()));
        }
        Ok(Template { pieces })
    }

    pub fn render(&self, ctx: &TemplateContext) -> String {
        let mut out = String::new();
        for piece in &self.pieces {
            match piece {
                Piece::Text(t) => out.push_str(t),
                Piece::Value(p) => match p {
                    Placeholder::SourceIp => out.push_str(&ctx.source_ip),
                    Placeholder::Proto => out.push_str(&ctx.proto),
                    Placeholder::Port => out.push_str(&ctx.port),
                    Placeholder::Username => out.push_str(&shell_quote(&ctx.username)),
                    Placeholder::Timestamp => {
                        let _ = write!(out, "{}", ctx.timestamp);
                    }
                    Placeholder::Timeout => {
                        let _ = write!(out, "{}", ctx.timeout);
                    }
                    Placeholder::AccessMsg => out.push_str(&shell_quote(&ctx.access_msg)),
                    Placeholder::NatAccess => out.push_str(&shell_quote(&ctx.nat_access)),
                },
            }
        }
        out
    }
}

/// One POSIX shell word: `'…'` with embedded quotes as `'\''`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> TemplateContext {
        TemplateContext {
            source_ip: "10.0.0.1".into(),
            proto: "tcp".into(),
            port: "22".into(),
            username: "alice".into(),
            timestamp: 1_775_331_907,
            timeout: 60,
            access_msg: "10.0.0.1,tcp/22".into(),
            nat_access: "192.168.1.100,22".into(),
        }
    }

    #[test]
    fn renders_every_placeholder() {
        let t = Template::parse(
            "{{.SourceIP}} {{.Proto}} {{.Port}} {{.Username}} {{.Timestamp}} {{.Timeout}} {{.AccessMsg}} {{.NATAccess}}",
        )
        .unwrap();
        assert_eq!(
            t.render(&ctx()),
            "10.0.0.1 tcp 22 'alice' 1775331907 60 '10.0.0.1,tcp/22' '192.168.1.100,22'"
        );
    }

    #[test]
    fn spaces_inside_braces_and_literal_braces() {
        let t = Template::parse("a {{ .Port }} b { c } }} d").unwrap();
        assert_eq!(t.render(&ctx()), "a 22 b { c } }} d");
    }

    #[test]
    fn shipped_style_templates_parse() {
        for text in [
            "iptables -C FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT 2>/dev/null",
            "nft add rule inet fwknop input ip saddr {{.SourceIP}} {{.Proto}} dport {{.Port}} accept comment \\\"fwknop-{{.SourceIP}}-{{.Proto}}-{{.Port}}\\\"",
            "nft -a list chain inet fwknop input | grep 'fwknop-{{.SourceIP}}' | awk '{print $NF}' | xargs -I{} nft delete rule inet fwknop input handle {}",
        ] {
            Template::parse(text).unwrap();
        }
    }

    #[test]
    fn rejects_unsupported_constructs() {
        for bad in [
            "{{.Invalid",
            "{{.Typo}}",
            "{{if .NATAccess}}x{{end}}",
            "{{.Port | printf \"%s\"}}",
            "{{- .Port -}}",
            "{{Port}}",
            "{{}}",
        ] {
            assert!(Template::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_text_cannot_escape_quotes() {
        let mut c = ctx();
        c.username = "x'; rm -rf / #".into();
        let t = Template::parse("echo {{.Username}}").unwrap();
        assert_eq!(t.render(&c), r"echo 'x'\''; rm -rf / #'");
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(t.render(&c))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "x'; rm -rf / #\n");
    }

    #[test]
    fn empty_nat_access_renders_as_empty_word() {
        let mut c = ctx();
        c.nat_access.clear();
        assert_eq!(
            Template::parse("[{{.NATAccess}}]").unwrap().render(&c),
            "['']"
        );
    }
}
