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

use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "pwldapd",
    about = "LDAP daemon backed by the POSIX password database and PAM",
    long_about = "Serves local users and groups over LDAP (RFC 4510). \
                  Binds are authenticated via PAM. \
                  The base DN defaults to the domain derived from the \
                  system hostname. \
                  IPv6 addresses must use bracket notation, e.g. [::1]:389."
)]
pub struct Cli {
    /// Path to TOML configuration file.
    /// All options can be set in the file; CLI args take precedence.
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Plain (non-TLS) address to listen on. May be repeated.
    /// (IPv6: use bracket notation, e.g. [::1]:389)
    /// Default: 127.0.0.1:389
    #[arg(short, long, value_name = "ADDR")]
    pub listen: Vec<String>,

    /// TLS address to listen on. May be repeated.
    /// Requires --tls-cert and --tls-key.
    #[arg(long, value_name = "ADDR",
          requires = "tls_cert", requires = "tls_key")]
    pub tls_listen: Vec<String>,

    /// LDAP base DN (e.g. dc=example,dc=com) [default: derived from hostname]
    #[arg(short, long)]
    pub base_dn: Option<String>,

    /// Restrict served accounts to this UID range (e.g. 1000-65535 or 1001).
    /// May be repeated to allow multiple ranges.
    /// Default: 1000-65535
    #[arg(short = 'u', long = "uid-range", value_name = "N[-M]")]
    pub uid_ranges: Vec<config::UidRange>,

    /// Restrict served groups to this GID range (e.g. 1000-65535 or 200).
    /// May be repeated to allow multiple ranges.
    /// Primary groups of served users are always included.
    #[arg(short = 'g', long = "gid-range", value_name = "N[-M]")]
    pub gid_ranges: Vec<config::GidRange>,

    /// Path to PEM-encoded TLS certificate (requires --tls-key)
    #[arg(long, requires = "tls_key", value_name = "FILE")]
    pub tls_cert: Option<PathBuf>,

    /// Path to PEM-encoded TLS private key (requires --tls-cert)
    #[arg(long, requires = "tls_cert", value_name = "FILE")]
    pub tls_key: Option<PathBuf>,
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

    if !cli.tls_listen.is_empty()
        && (cli.tls_cert.is_none() || cli.tls_key.is_none())
    {
        bail!("--tls-listen requires --tls-cert and --tls-key");
    }

    let file_config = match cli.config.as_deref() {
        Some(path) => Some(config::load_file_config(path)?),
        None => None,
    };

    let cfg = config::merge_config(cli, file_config)?;

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
