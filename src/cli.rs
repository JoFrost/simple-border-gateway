use std::path::PathBuf;

use clap::Parser;
use log::LevelFilter;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Log level, defaults to INFO
    #[arg(short = 'l', long, value_name = "LEVEL")]
    pub log_level: Option<LevelFilter>,

    /// Only start the configured inbound proxy
    #[arg(
        short = 'i',
        long,
        default_value = "false",
        conflicts_with = "outbound_only"
    )]
    pub inbound_only: bool,

    /// Only start the configured outbound proxy
    #[arg(
        short = 'o',
        long,
        default_value = "false",
        conflicts_with = "inbound_only"
    )]
    pub outbound_only: bool,

    /// Sets a custom config file
    #[arg(short = 'c', long, value_name = "FILE", default_value = "config.toml")]
    pub config_file: PathBuf,

    /// Reject every default endpoint that is not explicitly allowed by an override rule.
    #[arg(long, default_value = "false")]
    pub reject_all_by_default: bool,
}

pub fn parse_cli() -> Result<Cli, clap::Error> {
    Cli::try_parse()
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{Parser, error::ErrorKind};

    #[test]
    fn inbound_only_conflicts_with_outbound_only() {
        let error =
            Cli::try_parse_from(["simple-border-gateway", "--inbound-only", "--outbound-only"])
                .err()
                .expect("conflicting modes should fail parsing");

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }
}
