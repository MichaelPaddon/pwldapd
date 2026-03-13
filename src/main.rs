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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pwldapd=info".into()),
        )
        .init();

    let cli = Cli::parse();

    let file_config = match cli.config.as_deref() {
        Some(path) => Some(config::load_file_config(path)?),
        None => None,
    };

    let cfg = config::merge_config(file_config)?;

    let uid_ranges_s: Vec<String> = cfg.uid_ranges.iter()
        .map(|r| format!("{}-{}", r.start(), r.end()))
        .collect();
    let gid_ranges_s: Vec<String> = cfg.gid_ranges.iter()
        .map(|r| format!("{}-{}", r.start(), r.end()))
        .collect();
    let gid_ranges_display = if gid_ranges_s.is_empty() {
        "all".to_string()
    } else {
        gid_ranges_s.join(",")
    };
    info!(
        "base_dn={} uid_ranges={} gid_ranges={}",
        cfg.base_dn, uid_ranges_s.join(","), gid_ranges_display
    );

    pam_auth::check_pam_service();

    server::run(cfg).await
}
