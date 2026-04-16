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
use std::path::PathBuf;
use tracing::info;

fn parse_args() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => match args.next() {
                Some(path) => return Some(PathBuf::from(path)),
                None => {
                    eprintln!("error: '{}' requires a FILE argument", arg);
                    std::process::exit(1);
                }
            },
            "-h" | "--help" => {
                println!(
                    "Usage: pwldapd [-c FILE]\n\
                     \nOptions:\n  \
                     -c, --config FILE  Path to TOML configuration file\n  \
                     -h, --help         Print this help message\n  \
                     -V, --version      Print version"
                );
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("pwldapd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unexpected argument '{other}'; try --help");
                std::process::exit(1);
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = parse_args();

    const DEFAULT_CONFIG: &str = "/etc/pwldapd.toml";

    let file_config = if let Some(path) = config_path.as_deref() {
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
