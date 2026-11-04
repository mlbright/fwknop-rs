//! The client's command-line flags, with fwknop-go's names and semantics.
//!
//! Every field is optional so the config loader can tell a flag that was
//! given from one that was not; defaults are applied as the lowest config
//! layer instead. Bool flags take an optional `=value` (`--use-hmac=false`)
//! and ints accept Go's prefixes (`0x10`), as pflag does.

use clap::{ArgAction, Parser};

use cli_common::layers::{parse_go_bool, parse_go_int};

#[derive(Debug, Parser, Default)]
#[command(
    name = "fwknop",
    about = "Send a Single Packet Authorization (SPA) request to an fwknopd server",
    disable_version_flag = true,
    // Like pflag, a repeated flag replaces the earlier value.
    args_override_self = true
)]
pub struct Cli {
    // Target
    /// Hostname or IP of the fwknop server
    #[arg(short = 'D', long)]
    pub destination: Option<String>,
    /// Destination port for SPA packet [default: 62201]
    #[arg(short = 'p', long, value_parser = go_int, value_name = "PORT")]
    pub server_port: Option<i64>,

    // SPA message
    /// Source IP to allow in SPA packet
    #[arg(short = 'a', long)]
    pub allow_ip: Option<String>,
    /// Ports/protocols to open (e.g. tcp/22)
    #[arg(short = 'A', long)]
    pub access: Option<String>,
    /// Command for server to execute
    #[arg(short = 'C', long)]
    pub server_cmd: Option<String>,
    /// Override username in SPA packet
    #[arg(short = 'U', long)]
    pub spoof_user: Option<String>,
    /// Use 0.0.0.0 as source IP
    #[arg(short = 's', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub source_ip: Option<bool>,
    /// Firewall rule timeout (seconds)
    #[arg(short = 'f', long, value_parser = go_int, value_name = "SECONDS")]
    pub fw_timeout: Option<i64>,
    /// NAT access (IP,port)
    #[arg(short = 'N', long)]
    pub nat_access: Option<String>,
    /// Local NAT access
    #[arg(long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub nat_local: Option<bool>,

    // Crypto
    /// Digest algorithm [default: sha256]
    #[arg(short = 'm', long)]
    pub digest_type: Option<String>,
    /// HMAC digest algorithm [default: sha256]
    #[arg(long)]
    pub hmac_digest_type: Option<String>,
    /// AES encryption mode (cbc, legacy) [default: cbc]
    #[arg(long)]
    pub encryption_mode: Option<String>,
    /// Encryption key (passphrase)
    #[arg(long)]
    pub key: Option<String>,
    /// Base64-encoded encryption key
    #[arg(long)]
    pub key_base64: Option<String>,
    /// HMAC key
    #[arg(long)]
    pub key_hmac: Option<String>,
    /// Base64-encoded HMAC key
    #[arg(long)]
    pub key_base64_hmac: Option<String>,
    /// Enable HMAC authentication [default: true]
    #[arg(long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub use_hmac: Option<bool>,

    // IP resolution
    /// Resolve external IP via HTTPS
    #[arg(short = 'R', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub resolve_ip: Option<bool>,
    /// URL for external IP resolution [default: https://api.ipify.org]
    #[arg(long)]
    pub resolve_url: Option<String>,

    // Time
    /// Add time offset to timestamp
    #[arg(long, allow_hyphen_values = true)]
    pub time_offset_plus: Option<String>,
    /// Subtract time offset from timestamp
    #[arg(long, allow_hyphen_values = true)]
    pub time_offset_minus: Option<String>,

    // RC file
    /// Named stanza in .fwknoprc
    #[arg(short = 'n', long)]
    pub named_config: Option<String>,
    /// Path to fwknoprc file
    #[arg(long)]
    pub rc_file: Option<String>,
    /// Skip .fwknoprc
    #[arg(long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub no_rc_file: Option<bool>,
    /// List stanzas in rc file
    #[arg(long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub stanza_list: Option<bool>,

    // Modes
    /// Build packet but don't send
    #[arg(short = 'T', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub test: Option<bool>,
    /// Verbose output (repeatable)
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,
    /// Generate encryption + HMAC keys
    #[arg(short = 'k', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub key_gen: Option<bool>,
    /// Print version
    #[arg(short = 'V', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub version: Option<bool>,

    /// Arguments that are not flags are ignored, as fwknop-go does.
    #[arg(hide = true)]
    pub ignored: Vec<String>,
}

fn go_bool(s: &str) -> Result<bool, String> {
    parse_go_bool(s)
}

fn go_int(s: &str) -> Result<i64, String> {
    parse_go_int(s)
}
