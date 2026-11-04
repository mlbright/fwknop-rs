//! `fwknop-convert`: converts legacy C fwknop configuration files to the
//! YAML that fwknop-rs reads.
//!
//! ```text
//! fwknop-convert --type client --input ~/.fwknoprc
//! fwknop-convert --type server --input /etc/fwknop/fwknopd.conf
//! fwknop-convert --type access --input /etc/fwknop/access.conf
//! ```
//!
//! The YAML goes to stdout; warnings about keys that have no equivalent go
//! to stderr.

mod access;
mod client;
mod server;
mod yaml;

use std::io::Write;
use std::process::ExitCode;

use anyhow::{Result, anyhow, bail};
use clap::{CommandFactory, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "fwknop-convert",
    about = "Convert legacy C fwknop configuration files to YAML",
    override_usage = "fwknop-convert --type <client|server|access> --input <file>",
    disable_version_flag = true,
    args_override_self = true
)]
struct Cli {
    /// Conversion type: client, server, or access
    #[arg(short = 't', long = "type", default_value = "")]
    conv_type: String,
    /// Input file path
    #[arg(short = 'i', long, default_value = "")]
    input: String,
    /// Print version
    #[arg(short = 'V', long)]
    version: bool,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    match run(&cli, &mut stdout.lock(), &mut stderr.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fwknop-convert: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli, out: &mut dyn Write, err: &mut dyn Write) -> Result<()> {
    if cli.version {
        let info = buildinfo::Info::new(env!("CARGO_PKG_VERSION"));
        writeln!(out, "fwknop-convert version {info}")?;
        return Ok(());
    }
    if cli.input.is_empty() {
        let _ = write!(err, "{}", Cli::command().render_help());
        bail!("--input is required");
    }
    let (yaml, warnings) = match cli.conv_type.as_str() {
        "client" => convert_client(&cli.input)?,
        "server" => convert_server(&cli.input)?,
        "access" => convert_access(&cli.input)?,
        _ => {
            let _ = write!(err, "{}", Cli::command().render_help());
            bail!("--type must be client, server, or access");
        }
    };
    for w in warnings {
        writeln!(err, "warning: {w}")?;
    }
    out.write_all(yaml.as_bytes())?;
    Ok(())
}

fn convert_client(path: &str) -> Result<(String, Vec<String>)> {
    let data = std::fs::read_to_string(path).map_err(|e| anyhow!("reading rc file: {e}"))?;
    let (stanzas, warnings) = client::parse_client_stanzas(&data);
    if stanzas.is_empty() {
        bail!("no stanzas found in {path}");
    }
    Ok((client::render_client(&stanzas), warnings))
}

fn convert_server(path: &str) -> Result<(String, Vec<String>)> {
    let data = std::fs::read_to_string(path).map_err(|e| anyhow!("reading server config: {e}"))?;
    let conv = server::parse_server_config(&data);
    let warnings = conv.warnings.clone();
    Ok((server::render_server(&conv), warnings))
}

fn convert_access(path: &str) -> Result<(String, Vec<String>)> {
    let data = std::fs::read_to_string(path).map_err(|e| anyhow!("reading access config: {e}"))?;
    let (stanzas, warnings) = access::parse_access_config(&data);
    if stanzas.is_empty() {
        bail!("no access stanzas found in {path}");
    }
    Ok((access::render_access(&stanzas), warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args(args: &[&str]) -> (Result<()>, String, String) {
        let cli =
            Cli::try_parse_from(std::iter::once("fwknop-convert").chain(args.iter().copied()))
                .unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let r = run(&cli, &mut out, &mut err);
        (
            r,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn file(text: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f
    }

    #[test]
    fn client_end_to_end() {
        let f = file("[default]\nSPA_SERVER 10.0.0.1\nACCESS tcp/22\nBOGUS 1\n");
        let (r, out, err) = run_args(&["--type", "client", "--input", f.path().to_str().unwrap()]);
        r.unwrap();
        assert_eq!(out, "default:\n  access: tcp/22\n  destination: 10.0.0.1\n");
        assert_eq!(
            err,
            "warning: skipping unsupported key BOGUS in stanza [default]\n"
        );
    }

    #[test]
    fn server_end_to_end() {
        let f = file("UDPSERV_PORT 62201;\nPF_ANCHOR_NAME fwknop;\n");
        let (r, out, _) = run_args(&["-t", "server", "-i", f.path().to_str().unwrap()]);
        r.unwrap();
        assert!(out.starts_with("# Detected pf firewall configuration from legacy config.\n"));
        assert!(out.contains("action_template: pf.yaml\n"));
    }

    #[test]
    fn access_end_to_end_and_empty() {
        let f = file("SOURCE ANY\nKEY k\n");
        let (r, out, _) = run_args(&["--type", "access", "--input", f.path().to_str().unwrap()]);
        r.unwrap();
        assert_eq!(out, "- key: k\n  source: ANY\n");

        let empty = file("# nothing here\n");
        let (r, _, _) = run_args(&[
            "--type",
            "access",
            "--input",
            empty.path().to_str().unwrap(),
        ]);
        assert!(
            r.unwrap_err()
                .to_string()
                .starts_with("no access stanzas found")
        );
    }

    #[test]
    fn errors() {
        let (r, _, err) = run_args(&["--type", "client"]);
        assert_eq!(r.unwrap_err().to_string(), "--input is required");
        assert!(err.contains("Usage: fwknop-convert --type"));
        let (r, _, _) = run_args(&["--type", "bogus", "--input", "/x"]);
        assert_eq!(
            r.unwrap_err().to_string(),
            "--type must be client, server, or access"
        );
        for (t, prefix) in [
            ("client", "reading rc file"),
            ("server", "reading server config"),
            ("access", "reading access config"),
        ] {
            let (r, _, _) = run_args(&["--type", t, "--input", "/nonexistent/file"]);
            assert!(r.unwrap_err().to_string().starts_with(prefix), "{t}");
        }
    }

    #[test]
    fn version() {
        let (r, out, _) = run_args(&["-V"]);
        r.unwrap();
        assert!(out.starts_with("fwknop-convert version 0.1.0"), "{out}");
    }
}
