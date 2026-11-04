//! Helpers shared by the fwknop-rs binaries.
//!
//! - [`layers`]: configuration merged from defaults, a YAML file,
//!   environment variables and flags, with fwknop-go's (koanf's) precedence
//!   and loose type conversions.
//! - [`time`]: timestamps formatted the way fwknop-go prints them.

pub mod layers;
pub mod time;
