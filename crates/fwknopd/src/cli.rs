//! fwknopd's command-line flags, with fwknop-go's names and semantics.

use clap::Parser;

use cli_common::layers::parse_go_bool;

#[derive(Debug, Clone, Parser, Default)]
#[command(
    name = "fwknopd",
    about = "Receive Single Packet Authorization (SPA) packets and open firewall access",
    disable_version_flag = true,
    args_override_self = true
)]
pub struct Cli {
    /// Server config YAML file [default: /etc/fwknop/server.yaml]
    #[arg(short = 'c', long)]
    pub config_file: Option<String>,
    /// Access rules YAML file [default: /etc/fwknop/access.yaml]
    #[arg(short = 'a', long)]
    pub access_file: Option<String>,
    /// Dump current config and exit
    #[arg(short = 'D', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub dump_config: Option<bool>,
    /// Run in foreground (don't daemonize)
    #[arg(short = 'f', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub foreground: Option<bool>,
    /// Kill running fwknopd
    #[arg(short = 'K', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub kill: Option<bool>,
    /// PID file path
    #[arg(short = 'p', long)]
    pub pid_file: Option<String>,
    /// Restart running fwknopd
    #[arg(short = 'R', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub restart: Option<bool>,
    /// Show status of running fwknopd
    #[arg(short = 'S', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub status: Option<bool>,
    /// Test mode (parse packets, log only)
    #[arg(short = 't', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub test: Option<bool>,
    /// Verbose mode
    #[arg(short = 'v', long, num_args = 0..=1, require_equals = true,
          default_missing_value = "true", value_parser = go_bool, value_name = "BOOL")]
    pub verbose: Option<bool>,
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
