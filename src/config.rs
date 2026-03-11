use anyhow::{bail, Result};
use std::ffi::{CStr, CString};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::ptr;

#[derive(Debug, Clone)]
pub struct Config {
    /// Plain (non-TLS) listen addresses.
    pub listen: Vec<String>,
    /// TLS listen addresses. Requires tls_cert and tls_key.
    pub tls_listen: Vec<String>,
    pub base_dn: String,
    /// UID ranges to serve. Empty means serve all UIDs.
    pub uid_ranges: Vec<RangeInclusive<u32>>,
    /// GID ranges to serve. Empty means serve all GIDs.
    /// Groups that are a primary GID of a served user are always included.
    pub gid_ranges: Vec<RangeInclusive<u32>>,
    /// PEM TLS certificate path. Required when tls_listen is non-empty.
    pub tls_cert: Option<PathBuf>,
    /// PEM TLS private key path. Required when tls_listen is non-empty.
    pub tls_key: Option<PathBuf>,
}

impl Config {
    pub fn users_dn(&self) -> String {
        format!("ou=people,{}", self.base_dn)
    }

    pub fn groups_dn(&self) -> String {
        format!("ou=groups,{}", self.base_dn)
    }

    /// Returns true if `uid` should be served under the current configuration.
    pub fn uid_allowed(&self, uid: u32) -> bool {
        self.uid_ranges.is_empty()
            || self.uid_ranges.iter().any(|r| r.contains(&uid))
    }

    /// Returns true if `gid` should be served under the current configuration.
    /// Does not account for primary-GID promotion; call site must handle that.
    pub fn gid_allowed(&self, gid: u32) -> bool {
        self.gid_ranges.is_empty()
            || self.gid_ranges.iter().any(|r| r.contains(&gid))
    }
}

/// A UID range specification parsed from a CLI argument:
/// `N` or `N-M` (inclusive).
#[derive(Debug, Clone)]
pub struct UidRange(pub RangeInclusive<u32>);

impl std::str::FromStr for UidRange {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        Ok(UidRange(parse_id_range(s, "UID")?))
    }
}

/// A GID range specification parsed from a CLI argument:
/// `N` or `N-M` (inclusive).
#[derive(Debug, Clone)]
pub struct GidRange(pub RangeInclusive<u32>);

impl std::str::FromStr for GidRange {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        Ok(GidRange(parse_id_range(s, "GID")?))
    }
}

fn parse_id_range(
    s: &str,
    label: &str,
) -> std::result::Result<RangeInclusive<u32>, String> {
    match s.split_once('-') {
        Some((lo, hi)) => {
            let lo: u32 = lo.trim().parse()
                .map_err(|_| format!("invalid {label} {lo:?}"))?;
            let hi: u32 = hi.trim().parse()
                .map_err(|_| format!("invalid {label} {hi:?}"))?;
            if lo > hi {
                return Err(format!(
                    "range start {lo} is greater than end {hi}"
                ));
            }
            Ok(lo..=hi)
        }
        None => {
            let n: u32 = s.trim().parse()
                .map_err(|_| format!("invalid {label} {s:?}"))?;
            Ok(n..=n)
        }
    }
}

/// Derive the base DN from the system hostname, consulting DNS for the FQDN
/// if the hostname is unqualified. Returns an error if the domain cannot be
/// determined — the caller should ask the user to supply --base-dn.
pub fn derive_base_dn() -> Result<String> {
    let hostname = system_hostname()?;

    if let Some(dn) = base_dn_from_hostname(&hostname) {
        return Ok(dn);
    }

    // Short hostname — try getaddrinfo(AI_CANONNAME) to find the FQDN.
    if let Some(fqdn) = canonical_name(&hostname) {
        if let Some(dn) = base_dn_from_hostname(&fqdn) {
            return Ok(dn);
        }
    }

    bail!(
        "Cannot derive base DN from hostname {:?}. \
         Specify --base-dn (e.g. --base-dn dc=example,dc=com).",
        hostname
    )
}

// Internals

fn base_dn_from_hostname(hostname: &str) -> Option<String> {
    let dot = hostname.find('.')?;
    let domain = &hostname[dot + 1..];
    // Reject placeholder domains that don't identify a real organisation.
    if domain.is_empty() || matches!(domain, "local" | "localdomain") {
        return None;
    }
    Some(domain_to_base_dn(hostname))
}

fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| format!("dc={p}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn system_hostname() -> Result<String> {
    let mut buf = vec![0u8; 256];
    let rc = unsafe {
        libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    if rc != 0 {
        bail!("gethostname(2) failed: {}", std::io::Error::last_os_error());
    }
    let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();
    Ok(s)
}

fn canonical_name(hostname: &str) -> Option<String> {
    let c_host = CString::new(hostname).ok()?;
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_CANONNAME;
    // avoid duplicate results per address family
    hints.ai_socktype = libc::SOCK_STREAM;

    let mut res: *mut libc::addrinfo = ptr::null_mut();
    let rc = unsafe {
        libc::getaddrinfo(c_host.as_ptr(), ptr::null(), &hints, &mut res)
    };
    if rc != 0 || res.is_null() {
        return None;
    }

    let name = unsafe {
        if (*res).ai_canonname.is_null() {
            None
        } else {
            Some(
                CStr::from_ptr((*res).ai_canonname)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    };
    unsafe { libc::freeaddrinfo(res) };
    name
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_derives_base_dn() {
        assert_eq!(
            base_dn_from_hostname("server.example.com").unwrap(),
            "dc=server,dc=example,dc=com"
        );
    }

    #[test]
    fn multi_label_domain() {
        assert_eq!(
            base_dn_from_hostname("host.sub.example.co.uk").unwrap(),
            "dc=host,dc=sub,dc=example,dc=co,dc=uk"
        );
    }

    #[test]
    fn bare_hostname_returns_none() {
        assert!(base_dn_from_hostname("myserver").is_none());
    }

    #[test]
    fn local_domain_rejected() {
        assert!(base_dn_from_hostname("host.local").is_none());
        assert!(base_dn_from_hostname("host.localdomain").is_none());
    }

    #[test]
    fn domain_to_base_dn_conversion() {
        assert_eq!(domain_to_base_dn("example.com"), "dc=example,dc=com");
        assert_eq!(domain_to_base_dn("a.b.c"), "dc=a,dc=b,dc=c");
    }

    // UidRange parsing

    #[test]
    fn uid_range_single() {
        let r: UidRange = "1000".parse().unwrap();
        assert_eq!(r.0, 1000..=1000);
    }

    #[test]
    fn uid_range_range() {
        let r: UidRange = "1000-65535".parse().unwrap();
        assert_eq!(r.0, 1000..=65535);
    }

    #[test]
    fn uid_range_single_value_range() {
        let r: UidRange = "42-42".parse().unwrap();
        assert_eq!(r.0, 42..=42);
    }

    #[test]
    fn uid_range_invalid_not_a_number() {
        assert!("abc".parse::<UidRange>().is_err());
        assert!("1000-abc".parse::<UidRange>().is_err());
    }

    #[test]
    fn uid_range_invalid_reversed() {
        assert!("2000-1000".parse::<UidRange>().is_err());
    }

    // Config::uid_allowed and gid_allowed

    fn cfg_with_ranges(ranges: &[RangeInclusive<u32>]) -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            base_dn: String::new(),
            uid_ranges: ranges.to_vec(),
            gid_ranges: vec![],
            tls_cert: None,
            tls_key: None,
        }
    }

    #[test]
    fn uid_allowed_no_ranges_permits_all() {
        let cfg = cfg_with_ranges(&[]);
        assert!(cfg.uid_allowed(0));
        assert!(cfg.uid_allowed(1000));
        assert!(cfg.uid_allowed(u32::MAX));
    }

    #[test]
    fn uid_allowed_single_range() {
        let cfg = cfg_with_ranges(&[1000..=65535]);
        assert!(!cfg.uid_allowed(0));
        assert!(!cfg.uid_allowed(999));
        assert!(cfg.uid_allowed(1000));
        assert!(cfg.uid_allowed(65535));
        assert!(!cfg.uid_allowed(65536));
    }

    #[test]
    fn uid_allowed_multiple_ranges() {
        let cfg = cfg_with_ranges(&[1000..=1999, 3000..=3999]);
        assert!(cfg.uid_allowed(1000));
        assert!(cfg.uid_allowed(1999));
        assert!(!cfg.uid_allowed(2000));
        assert!(cfg.uid_allowed(3000));
        assert!(!cfg.uid_allowed(4000));
    }

    #[test]
    fn uid_allowed_single_uid_range() {
        let cfg = cfg_with_ranges(&[1001..=1001]);
        assert!(cfg.uid_allowed(1001));
        assert!(!cfg.uid_allowed(1000));
        assert!(!cfg.uid_allowed(1002));
    }

    fn cfg_with_gid_ranges(ranges: &[RangeInclusive<u32>]) -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            base_dn: String::new(),
            uid_ranges: vec![],
            gid_ranges: ranges.to_vec(),
            tls_cert: None,
            tls_key: None,
        }
    }

    #[test]
    fn gid_allowed_no_ranges_permits_all() {
        let cfg = cfg_with_gid_ranges(&[]);
        assert!(cfg.gid_allowed(0));
        assert!(cfg.gid_allowed(1000));
        assert!(cfg.gid_allowed(u32::MAX));
    }

    #[test]
    fn gid_allowed_single_range() {
        let cfg = cfg_with_gid_ranges(&[1000..=65535]);
        assert!(!cfg.gid_allowed(0));
        assert!(!cfg.gid_allowed(999));
        assert!(cfg.gid_allowed(1000));
        assert!(cfg.gid_allowed(65535));
        assert!(!cfg.gid_allowed(65536));
    }

    #[test]
    fn gid_allowed_multiple_ranges() {
        let cfg = cfg_with_gid_ranges(&[100..=199, 300..=399]);
        assert!(cfg.gid_allowed(100));
        assert!(!cfg.gid_allowed(200));
        assert!(cfg.gid_allowed(300));
        assert!(!cfg.gid_allowed(400));
    }
}
