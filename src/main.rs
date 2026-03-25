//! `pwldapd` — a read-only LDAP server backed by the local POSIX user and
//! group database. Bind requests are authenticated via PAM. All other write
//! operations are rejected. See the man page (`man pwldapd`) for full details.

mod ber;
mod config;
mod handler;
mod ldap;
mod passwd;
mod pam_auth;
mod server;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "pwldapd",
    version,
    about = "LDAP daemon backed by the POSIX password database and PAM",
    long_about = "Serves local users and groups over LDAP (RFC 4510). \
                  Binds are authenticated via PAM. \
                  All options are set via the TOML configuration file. \
                  See pwldapd(8) for details."
)]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    const DEFAULT_CONFIG: &str = "/etc/pwldapd.conf";

    let file_config = if let Some(path) = cli.config.as_deref() {
        Some(config::load_file_config(path)?)
    } else if std::path::Path::new(DEFAULT_CONFIG).exists() {
        Some(config::load_file_config(std::path::Path::new(DEFAULT_CONFIG))?)
    } else {
        None
    };

    let log_filter = file_config
        .as_ref()
        .and_then(|fc| fc.log_level.as_deref())
        .map(tracing_subscriber::EnvFilter::new)
        .or_else(|| tracing_subscriber::EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| "pwldapd=info".into());

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .init();

    let cfg = config::merge_config(file_config)?;

    let fmt_ranges = |ranges: &[std::ops::RangeInclusive<u32>]| -> String {
        if ranges.is_empty() {
            "all".to_string()
        } else {
            ranges.iter()
                .map(|r| format!("{}-{}", r.start(), r.end()))
                .collect::<Vec<_>>()
                .join(",")
        }
    };
    info!(
        "base_dn={} uid_ranges={} gid_ranges={}",
        cfg.base_dn,
        fmt_ranges(&cfg.uid_ranges),
        fmt_ranges(&cfg.gid_ranges),
    );

    pam_auth::check_pam_service();

    server::run(cfg).await
}
