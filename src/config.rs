use anyhow::{bail, Result};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::ptr;

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

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
    /// Unix domain socket listeners.
    pub unix_listen: Vec<UnixSocket>,
    /// Extra attributes added to every user entry, in declaration order.
    pub user_attributes: Vec<(String, AttrValue)>,
    /// Per-user attribute overrides keyed by username. Fixed strings only;
    /// these take precedence over user_attributes.
    pub user_overrides: HashMap<String, HashMap<String, String>>,
    /// Usernames that must bind before searches are permitted.
    /// Empty means no bind required (anonymous access allowed).
    pub require_bind: Vec<String>,
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

    /// Returns true if `username` is permitted to perform searches.
    /// When `require_bind` is empty every client is permitted.
    pub fn bind_permitted(&self, username: &str) -> bool {
        self.require_bind.is_empty()
            || self.require_bind.iter().any(|u| u == username)
    }
}

// ---------------------------------------------------------------------------
// Attribute value: fixed string or template
// ---------------------------------------------------------------------------

/// A user attribute value: either a literal string or a template containing
/// `{placeholder}` sequences. Classification is done at config-load time;
/// a string is a `Template` if it contains `{`, `Fixed` otherwise.
///
/// Valid template placeholders:
/// `{uid}`, `{cn}`, `{sn}`, `{uidNumber}`, `{gidNumber}`,
/// `{homeDirectory}`, `{shell}`, `{gecos}`
#[derive(Debug, Clone)]
pub enum AttrValue {
    Fixed(String),
    Template(String),
}

/// Placeholder names accepted in template attribute values.
pub const KNOWN_VARS: &[&str] = &[
    "uid", "cn", "sn", "uidNumber", "gidNumber",
    "homeDirectory", "shell", "gecos",
];

/// Attributes that cannot be overridden via config; attempts emit a warning.
pub const PROTECTED_ATTRS: &[&str] = &["objectClass", "uid", "uidNumber", "gidNumber"];

// ---------------------------------------------------------------------------
// Unix socket configuration
// ---------------------------------------------------------------------------

/// Runtime representation of a single Unix domain socket listener.
#[derive(Debug, Clone, PartialEq)]
pub struct UnixSocket {
    pub path: PathBuf,
    /// Optional owner (username or numeric UID) to `chown` after bind.
    pub owner: Option<String>,
    /// Optional group (group name or numeric GID) to `chown` after bind.
    pub group: Option<String>,
    /// Optional mode in chmod notation (e.g. `660` means `0o660`).
    /// Applied exactly after bind; if absent the system default is used.
    pub mode: Option<u32>,
}

/// Full inline-table form of a Unix socket entry in the config file.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixSocketFull {
    path:  PathBuf,
    owner: Option<String>,
    group: Option<String>,
    mode:  Option<u32>,
}

/// Accepts either a plain path string or an inline table with `path` + options.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum UnixSocketSpec {
    Path(PathBuf),
    Full(UnixSocketFull),
}

/// Reinterpret a decimal integer's digits as an octal mode value.
/// `660` → `0o660`; returns an error if any digit is 8 or 9.
fn parse_chmod_mode(n: u32) -> Result<u32> {
    u32::from_str_radix(&format!("{n}"), 8)
        .map_err(|_| anyhow::anyhow!("invalid mode {n}: digits must be in 0–7"))
}

// ---------------------------------------------------------------------------
// File config (TOML deserialization)
// ---------------------------------------------------------------------------

/// Deserializable representation of the TOML config file.
/// All fields are `Option<>` so the file may omit any subset of them.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Glob patterns of additional config files to load before this file.
    pub include:         Option<Vec<String>>,
    pub listen:          Option<Vec<String>>,
    pub tls_listen:      Option<Vec<String>>,
    pub base_dn:         Option<String>,
    pub uid_ranges:      Option<Vec<UidRange>>,
    pub gid_ranges:      Option<Vec<GidRange>>,
    pub tls_cert:        Option<PathBuf>,
    pub tls_key:         Option<PathBuf>,
    pub unix_listen:     Option<Vec<UnixSocketSpec>>,
    pub user_attributes: Option<HashMap<String, String>>,
    pub user_overrides:  Option<HashMap<String, HashMap<String, String>>>,
    pub log_level:       Option<String>,
    pub require_bind:    Option<Vec<String>>,
}

/// Load and parse a TOML config file from `path`, processing any `include`
/// glob patterns. Included files are merged first; the main file's values
/// take precedence over included ones. Includes are not processed recursively.
pub fn load_file_config(path: &Path) -> Result<FileConfig> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading config file {:?}: {e}", path))?;
    let mut fc: FileConfig = toml::from_str(&text)
        .map_err(|e| anyhow::anyhow!("parsing config file {:?}: {e}", path))?;

    let patterns = fc.include.take().unwrap_or_default();
    if patterns.is_empty() {
        return Ok(fc);
    }

    let mut included = FileConfig::default();
    for pattern in &patterns {
        let paths = glob::glob(pattern)
            .map_err(|e| anyhow::anyhow!("invalid include pattern {pattern:?}: {e}"))?;
        for entry in paths {
            let inc_path = entry
                .map_err(|e| anyhow::anyhow!("error expanding include pattern: {e}"))?;
            let inc_text = std::fs::read_to_string(&inc_path)
                .map_err(|e| anyhow::anyhow!("reading {:?}: {e}", inc_path))?;
            let mut inc_fc: FileConfig = toml::from_str(&inc_text)
                .map_err(|e| anyhow::anyhow!("parsing {:?}: {e}", inc_path))?;
            inc_fc.include = None; // no recursive includes
            included = merge_file_configs(included, inc_fc);
        }
    }
    // Main file wins over includes.
    Ok(merge_file_configs(included, fc))
}

/// Merge two `FileConfig` values. `overlay` wins over `base` for every field.
/// For map fields (`user_attributes`, `user_overrides`) both are merged with
/// overlay entries taking precedence on key collision.
fn merge_file_configs(base: FileConfig, overlay: FileConfig) -> FileConfig {
    FileConfig {
        include: None,
        listen:     overlay.listen.or(base.listen),
        tls_listen: overlay.tls_listen.or(base.tls_listen),
        base_dn:    overlay.base_dn.or(base.base_dn),
        uid_ranges: overlay.uid_ranges.or(base.uid_ranges),
        gid_ranges: overlay.gid_ranges.or(base.gid_ranges),
        tls_cert:    overlay.tls_cert.or(base.tls_cert),
        tls_key:     overlay.tls_key.or(base.tls_key),
        unix_listen: overlay.unix_listen.or(base.unix_listen),
        user_attributes: merge_maps(base.user_attributes, overlay.user_attributes),
        user_overrides: merge_override_maps(base.user_overrides, overlay.user_overrides),
        log_level: overlay.log_level.or(base.log_level),
        require_bind: overlay.require_bind.or(base.require_bind),
    }
}

fn merge_maps(
    base: Option<HashMap<String, String>>,
    overlay: Option<HashMap<String, String>>,
) -> Option<HashMap<String, String>> {
    match (base, overlay) {
        (None, x) | (x, None) => x,
        (Some(mut b), Some(o)) => {
            b.extend(o);
            Some(b)
        }
    }
}

fn merge_override_maps(
    base: Option<HashMap<String, HashMap<String, String>>>,
    overlay: Option<HashMap<String, HashMap<String, String>>>,
) -> Option<HashMap<String, HashMap<String, String>>> {
    match (base, overlay) {
        (None, x) | (x, None) => x,
        (Some(mut b), Some(o)) => {
            for (user, attrs) in o {
                b.entry(user).or_default().extend(attrs);
            }
            Some(b)
        }
    }
}

// ---------------------------------------------------------------------------
// Config merging
// ---------------------------------------------------------------------------

/// Append `:<port>` to `addr` if it does not already include a port number.
/// Detection works by attempting to parse as a `SocketAddr`: success means
/// a port is present; failure means none is, and the default is appended.
fn with_default_port(addr: &str, port: u16) -> String {
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        addr.to_string()
    } else {
        format!("{addr}:{port}")
    }
}

/// Build a `Config` from an optional file config, applying hardcoded defaults
/// for any fields not present in the file.
pub fn merge_config(file: Option<FileConfig>) -> Result<Config> {
    let fc = file.unwrap_or_default();

    let listen: Vec<String> = fc.listen
        .unwrap_or_else(|| vec!["127.0.0.1:389".into()])
        .into_iter()
        .map(|a| with_default_port(&a, 389))
        .collect();
    let tls_listen: Vec<String> = fc.tls_listen
        .unwrap_or_default()
        .into_iter()
        .map(|a| with_default_port(&a, 636))
        .collect();

    let base_dn = fc.base_dn
        .map(Ok)
        .unwrap_or_else(derive_base_dn)?;

    let uid_ranges: Vec<RangeInclusive<u32>> = fc.uid_ranges
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.0)
        .collect();

    let gid_ranges: Vec<RangeInclusive<u32>> = fc.gid_ranges
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.0)
        .collect();

    let tls_cert = fc.tls_cert;
    let tls_key  = fc.tls_key;
    let unix_listen = fc.unix_listen
        .unwrap_or_default()
        .into_iter()
        .map(|spec| match spec {
            UnixSocketSpec::Path(path) => Ok(UnixSocket { path, owner: None, group: None, mode: None }),
            UnixSocketSpec::Full(f) => Ok(UnixSocket {
                path: f.path,
                owner: f.owner,
                group: f.group,
                mode: f.mode.map(parse_chmod_mode).transpose()?,
            }),
        })
        .collect::<Result<Vec<_>>>()?;

    if !tls_listen.is_empty() && (tls_cert.is_none() || tls_key.is_none()) {
        anyhow::bail!("tls_listen requires tls_cert and tls_key");
    }

    let user_attributes =
        build_attr_values(fc.user_attributes.unwrap_or_default())?;
    let user_overrides = fc.user_overrides.unwrap_or_default();
    let require_bind = fc.require_bind.unwrap_or_default();

    // Warn at startup about any protected attributes in user_overrides.
    for (username, overrides) in &user_overrides {
        for attr_name in overrides.keys() {
            if PROTECTED_ATTRS.iter().any(|p| p.eq_ignore_ascii_case(attr_name)) {
                tracing::warn!(
                    "user_overrides.{username}: {attr_name} is protected \
                     and cannot be overridden; skipping"
                );
            }
        }
    }

    Ok(Config {
        listen,
        tls_listen,
        unix_listen,
        base_dn,
        uid_ranges,
        gid_ranges,
        tls_cert,
        tls_key,
        user_attributes,
        user_overrides,
        require_bind,
    })
}

/// Convert the raw `HashMap<String, String>` from the file into typed
/// `AttrValue`s, validating any template placeholders.
/// Protected attributes are warned about and skipped here so the warning
/// fires once at startup rather than once per user per search.
pub fn build_attr_values(
    raw: HashMap<String, String>,
) -> Result<Vec<(String, AttrValue)>> {
    let mut out = Vec::with_capacity(raw.len());
    for (name, value) in raw {
        if PROTECTED_ATTRS.iter().any(|p| p.eq_ignore_ascii_case(&name)) {
            tracing::warn!(
                "user_attributes: {name} is protected and cannot be \
                 overridden; skipping"
            );
            continue;
        }
        let av = if value.contains('{') {
            validate_template(&value, &name)?;
            AttrValue::Template(value)
        } else {
            AttrValue::Fixed(value)
        };
        out.push((name, av));
    }
    Ok(out)
}

/// Validate that all `{placeholder}` sequences in `template` are known.
/// Returns an error naming the bad placeholder and listing valid ones.
fn validate_template(template: &str, attr_name: &str) -> Result<()> {
    let mut s = template;
    while let Some(open) = s.find('{') {
        s = &s[open + 1..];
        match s.find('}') {
            None => bail!(
                "unclosed '{{' in user_attributes.{attr_name}"
            ),
            Some(close) => {
                let var = &s[..close];
                if !KNOWN_VARS.contains(&var) {
                    bail!(
                        "unknown placeholder {{{var}}} in \
                         user_attributes.{attr_name}; \
                         valid variables are: {}",
                        KNOWN_VARS.join(", ")
                    );
                }
                s = &s[close + 1..];
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UID / GID range types
// ---------------------------------------------------------------------------

/// A UID range specification parsed from a CLI argument or config file:
/// `N` or `N-M` (inclusive).
#[derive(Debug, Clone)]
pub struct UidRange(pub RangeInclusive<u32>);

impl std::str::FromStr for UidRange {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        Ok(UidRange(parse_id_range(s, "UID")?))
    }
}

impl<'de> serde::Deserialize<'de> for UidRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A GID range specification parsed from a CLI argument or config file:
/// `N` or `N-M` (inclusive).
#[derive(Debug, Clone)]
pub struct GidRange(pub RangeInclusive<u32>);

impl std::str::FromStr for GidRange {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        Ok(GidRange(parse_id_range(s, "GID")?))
    }
}

impl<'de> serde::Deserialize<'de> for GidRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
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

// ---------------------------------------------------------------------------
// Base DN derivation
// ---------------------------------------------------------------------------

/// Derive the base DN from the system hostname, consulting DNS for the FQDN
/// if the hostname is unqualified. Returns an error if the domain cannot be
/// determined — the caller should ask the user to supply --base-dn.
pub fn derive_base_dn() -> Result<String> {
    let hostname = system_hostname()?;

    if let Some(dn) = base_dn_from_hostname(&hostname) {
        return Ok(dn);
    }

    // Short hostname — try getaddrinfo(AI_CANONNAME) to find the FQDN.
    if let Some(fqdn) = canonical_name(&hostname)
        && let Some(dn) = base_dn_from_hostname(&fqdn)
    {
        return Ok(dn);
    }

    bail!(
        "Cannot derive base DN from hostname {:?}. \
         Set base_dn in the configuration file (e.g. base_dn = \"dc=example,dc=com\").",
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config() -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            unix_listen: vec![],
            base_dn: String::new(),
            uid_ranges: vec![],
            gid_ranges: vec![],
            tls_cert: None,
            tls_key: None,
            user_attributes: vec![],
            user_overrides: HashMap::new(),
            require_bind: vec![],
        }
    }

    // Base DN derivation

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

    #[test]
    fn uid_allowed_no_ranges_permits_all() {
        let cfg = empty_config();
        assert!(cfg.uid_allowed(0));
        assert!(cfg.uid_allowed(1000));
        assert!(cfg.uid_allowed(u32::MAX));
    }

    #[test]
    fn uid_allowed_single_range() {
        let mut cfg = empty_config();
        cfg.uid_ranges = vec![1000..=65535];
        assert!(!cfg.uid_allowed(0));
        assert!(!cfg.uid_allowed(999));
        assert!(cfg.uid_allowed(1000));
        assert!(cfg.uid_allowed(65535));
        assert!(!cfg.uid_allowed(65536));
    }

    #[test]
    fn uid_allowed_multiple_ranges() {
        let mut cfg = empty_config();
        cfg.uid_ranges = vec![1000..=1999, 3000..=3999];
        assert!(cfg.uid_allowed(1000));
        assert!(cfg.uid_allowed(1999));
        assert!(!cfg.uid_allowed(2000));
        assert!(cfg.uid_allowed(3000));
        assert!(!cfg.uid_allowed(4000));
    }

    #[test]
    fn uid_allowed_single_uid_range() {
        let mut cfg = empty_config();
        cfg.uid_ranges = vec![1001..=1001];
        assert!(cfg.uid_allowed(1001));
        assert!(!cfg.uid_allowed(1000));
        assert!(!cfg.uid_allowed(1002));
    }

    #[test]
    fn gid_allowed_no_ranges_permits_all() {
        let cfg = empty_config();
        assert!(cfg.gid_allowed(0));
        assert!(cfg.gid_allowed(1000));
        assert!(cfg.gid_allowed(u32::MAX));
    }

    #[test]
    fn gid_allowed_single_range() {
        let mut cfg = empty_config();
        cfg.gid_ranges = vec![1000..=65535];
        assert!(!cfg.gid_allowed(0));
        assert!(!cfg.gid_allowed(999));
        assert!(cfg.gid_allowed(1000));
        assert!(cfg.gid_allowed(65535));
        assert!(!cfg.gid_allowed(65536));
    }

    #[test]
    fn gid_allowed_multiple_ranges() {
        let mut cfg = empty_config();
        cfg.gid_ranges = vec![100..=199, 300..=399];
        assert!(cfg.gid_allowed(100));
        assert!(!cfg.gid_allowed(200));
        assert!(cfg.gid_allowed(300));
        assert!(!cfg.gid_allowed(400));
    }

    // Template validation

    #[test]
    fn valid_template_accepted() {
        assert!(validate_template("{uid}@example.com", "mail").is_ok());
        assert!(validate_template("{uid}-{uidNumber}", "x").is_ok());
        assert!(validate_template("no placeholders", "x").is_ok());
    }

    #[test]
    fn unknown_placeholder_rejected() {
        assert!(validate_template("{email}@example.com", "mail").is_err());
    }

    #[test]
    fn unclosed_brace_rejected() {
        assert!(validate_template("{uid", "mail").is_err());
    }

    // build_attr_values

    #[test]
    fn build_attr_values_classifies_correctly() {
        let raw: HashMap<String, String> = [
            ("mail".to_string(), "{uid}@example.com".to_string()),
            ("dept".to_string(), "Engineering".to_string()),
        ]
        .into();
        let attrs = build_attr_values(raw).unwrap();
        let mail = attrs.iter().find(|(k, _)| k == "mail").unwrap();
        let dept = attrs.iter().find(|(k, _)| k == "dept").unwrap();
        assert!(matches!(mail.1, AttrValue::Template(_)));
        assert!(matches!(dept.1, AttrValue::Fixed(_)));
    }

    #[test]
    fn build_attr_values_rejects_bad_template() {
        let raw: HashMap<String, String> =
            [("mail".to_string(), "{email}@example.com".to_string())].into();
        assert!(build_attr_values(raw).is_err());
    }

    // with_default_port

    #[test]
    fn default_port_added_when_absent() {
        assert_eq!(with_default_port("127.0.0.1", 389), "127.0.0.1:389");
        assert_eq!(with_default_port("0.0.0.0", 636),   "0.0.0.0:636");
        assert_eq!(with_default_port("[::1]", 389),      "[::1]:389");
        assert_eq!(with_default_port("[::]", 636),       "[::]:636");
    }

    #[test]
    fn default_port_not_added_when_present() {
        assert_eq!(with_default_port("127.0.0.1:389",  389), "127.0.0.1:389");
        assert_eq!(with_default_port("127.0.0.1:3389", 389), "127.0.0.1:3389");
        assert_eq!(with_default_port("[::1]:636",       636), "[::1]:636");
    }

    // GidRange parsing (parallel to UidRange)

    #[test]
    fn gid_range_single() {
        let r: GidRange = "200".parse().unwrap();
        assert_eq!(r.0, 200..=200);
    }

    #[test]
    fn gid_range_range() {
        let r: GidRange = "100-999".parse().unwrap();
        assert_eq!(r.0, 100..=999);
    }

    #[test]
    fn gid_range_invalid() {
        assert!("abc".parse::<GidRange>().is_err());
        assert!("500-100".parse::<GidRange>().is_err());
    }

    // merge_config

    #[test]
    fn merge_config_no_file_uses_defaults() {
        // base_dn is derived from the system hostname, so just verify it
        // is non-empty and that the other defaults are applied.
        let cfg = merge_config(None).unwrap();
        assert_eq!(cfg.listen, vec!["127.0.0.1:389"]);
        assert!(cfg.uid_ranges.is_empty());
        assert!(cfg.gid_ranges.is_empty());
        assert!(cfg.tls_cert.is_none());
        assert!(cfg.user_attributes.is_empty());
        assert!(cfg.user_overrides.is_empty());
        assert!(cfg.unix_listen.is_empty());
        assert!(!cfg.base_dn.is_empty());
    }

    #[test]
    fn merge_config_file_values_applied() {
        let fc = FileConfig {
            listen: Some(vec!["0.0.0.0:3389".into()]),
            base_dn: Some("dc=test,dc=example,dc=com".into()),
            uid_ranges: Some(vec![UidRange(2000..=3000)]),
            ..Default::default()
        };
        let cfg = merge_config(Some(fc)).unwrap();
        assert_eq!(cfg.listen, vec!["0.0.0.0:3389"]);
        assert_eq!(cfg.base_dn, "dc=test,dc=example,dc=com");
        assert_eq!(cfg.uid_ranges, vec![2000..=3000]);
        assert!(cfg.gid_ranges.is_empty());
    }

    #[test]
    fn merge_config_tls_listen_without_cert_fails() {
        let fc = FileConfig {
            tls_listen: Some(vec!["0.0.0.0:636".into()]),
            base_dn: Some("dc=test,dc=com".into()),
            ..Default::default()
        };
        assert!(merge_config(Some(fc)).is_err());
    }

    // build_attr_values silently drops protected attrs

    #[test]
    fn build_attr_values_skips_protected_attrs() {
        let raw: HashMap<String, String> = [
            ("objectClass".to_string(), "hacker".to_string()),
            ("uid".to_string(), "injected".to_string()),
            ("mail".to_string(), "x@example.com".to_string()),
        ].into();
        let attrs = build_attr_values(raw).unwrap();
        assert!(!attrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("objectClass")));
        assert!(!attrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("uid")));
        assert!(attrs.iter().any(|(k, _)| k == "mail"));
    }

    // merge_file_configs

    #[test]
    fn merge_file_configs_overlay_wins_scalars() {
        let base = FileConfig {
            base_dn: Some("dc=base,dc=com".into()),
            listen:  Some(vec!["0.0.0.0:389".into()]),
            ..Default::default()
        };
        let overlay = FileConfig {
            base_dn: Some("dc=overlay,dc=com".into()),
            ..Default::default()
        };
        let merged = merge_file_configs(base, overlay);
        assert_eq!(merged.base_dn.as_deref(), Some("dc=overlay,dc=com"));
        assert_eq!(merged.listen.as_deref(), Some(&["0.0.0.0:389".to_string()][..]));
    }

    #[test]
    fn merge_file_configs_merges_user_attributes() {
        let base = FileConfig {
            user_attributes: Some([
                ("mail".into(), "{uid}@base.com".into()),
                ("dept".into(), "Base".into()),
            ].into()),
            ..Default::default()
        };
        let overlay = FileConfig {
            user_attributes: Some([
                ("mail".into(), "{uid}@overlay.com".into()),
                ("title".into(), "Staff".into()),
            ].into()),
            ..Default::default()
        };
        let merged = merge_file_configs(base, overlay);
        let ua = merged.user_attributes.unwrap();
        // overlay wins on collision
        assert_eq!(ua["mail"],  "{uid}@overlay.com");
        // base value preserved when no collision
        assert_eq!(ua["dept"],  "Base");
        // overlay-only value present
        assert_eq!(ua["title"], "Staff");
    }

    #[test]
    fn merge_file_configs_merges_user_overrides() {
        let base = FileConfig {
            user_overrides: Some([
                ("alice".into(), [("mail".into(), "old@x.com".into())].into()),
            ].into()),
            ..Default::default()
        };
        let overlay = FileConfig {
            user_overrides: Some([
                ("alice".into(), [("mail".into(), "new@x.com".into()),
                                  ("dept".into(), "Eng".into())].into()),
                ("bob".into(),   [("title".into(), "Admin".into())].into()),
            ].into()),
            ..Default::default()
        };
        let merged = merge_file_configs(base, overlay);
        let ov = merged.user_overrides.unwrap();
        assert_eq!(ov["alice"]["mail"], "new@x.com");
        assert_eq!(ov["alice"]["dept"], "Eng");
        assert_eq!(ov["bob"]["title"],  "Admin");
    }

    // TOML file config deserialization

    #[test]
    fn file_config_parses_empty() {
        let fc: FileConfig = toml::from_str("").unwrap();
        assert!(fc.listen.is_none());
        assert!(fc.user_attributes.is_none());
    }

    #[test]
    fn file_config_parses_user_attributes() {
        let toml = r#"
[user_attributes]
mail = "{uid}@example.com"
department = "Engineering"
"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let ua = fc.user_attributes.unwrap();
        assert_eq!(ua["mail"], "{uid}@example.com");
        assert_eq!(ua["department"], "Engineering");
    }

    #[test]
    fn file_config_parses_user_overrides() {
        let toml = r#"
[user_overrides.alice]
mail = "alice@external.com"
"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let ov = fc.user_overrides.unwrap();
        assert_eq!(ov["alice"]["mail"], "alice@external.com");
    }

    #[test]
    fn file_config_parses_unix_listen() {
        let toml = r#"unix_listen = ["/run/pwldapd/ldap.sock", "/tmp/ldap.sock"]"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let specs = fc.unix_listen.unwrap();
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn merge_config_unix_listen_applied() {
        let fc = FileConfig {
            unix_listen: Some(vec![
                UnixSocketSpec::Path("/run/pwldapd/ldap.sock".into()),
                UnixSocketSpec::Path("/tmp/ldap.sock".into()),
            ]),
            base_dn: Some("dc=test,dc=com".into()),
            ..Default::default()
        };
        let cfg = merge_config(Some(fc)).unwrap();
        assert_eq!(cfg.unix_listen[0].path, std::path::PathBuf::from("/run/pwldapd/ldap.sock"));
        assert_eq!(cfg.unix_listen[1].path, std::path::PathBuf::from("/tmp/ldap.sock"));
        assert_eq!(cfg.unix_listen[0].mode, None);
        assert_eq!(cfg.unix_listen[0].owner, None);
    }

    #[test]
    fn unix_listen_full_form_parses() {
        let toml = r#"
            unix_listen = [
                { path = "/run/pwldapd/ldap.sock", owner = "root", group = "ldap", mode = 660 },
            ]
            base_dn = "dc=test,dc=com"
        "#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        let cfg = merge_config(Some(fc)).unwrap();
        let sock = &cfg.unix_listen[0];
        assert_eq!(sock.path, std::path::PathBuf::from("/run/pwldapd/ldap.sock"));
        assert_eq!(sock.owner.as_deref(), Some("root"));
        assert_eq!(sock.group.as_deref(), Some("ldap"));
        assert_eq!(sock.mode, Some(0o660));
    }

    #[test]
    fn unix_listen_invalid_mode_rejected() {
        let toml = r#"
            unix_listen = [{ path = "/tmp/test.sock", mode = 689 }]
            base_dn = "dc=test,dc=com"
        "#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        assert!(merge_config(Some(fc)).is_err());
    }

    #[test]
    fn file_config_rejects_unknown_field() {
        assert!(toml::from_str::<FileConfig>("bogus_field = 1").is_err());
    }

    // require_bind

    #[test]
    fn file_config_parses_require_bind() {
        let toml = r#"require_bind = ["svcaccount", "monitor"]"#;
        let fc: FileConfig = toml::from_str(toml).unwrap();
        assert_eq!(fc.require_bind.unwrap(), vec!["svcaccount", "monitor"]);
    }

    #[test]
    fn merge_config_propagates_require_bind() {
        let fc = FileConfig {
            require_bind: Some(vec!["svc".into()]),
            base_dn: Some("dc=test,dc=com".into()),
            ..Default::default()
        };
        let cfg = merge_config(Some(fc)).unwrap();
        assert_eq!(cfg.require_bind, vec!["svc"]);
    }

    #[test]
    fn bind_permitted_empty_allows_all() {
        let cfg = empty_config();
        assert!(cfg.bind_permitted("anyone"));
        assert!(cfg.bind_permitted(""));
    }

    #[test]
    fn bind_permitted_with_list() {
        let mut cfg = empty_config();
        cfg.require_bind = vec!["svc".into(), "monitor".into()];
        assert!(cfg.bind_permitted("svc"));
        assert!(cfg.bind_permitted("monitor"));
        assert!(!cfg.bind_permitted("alice"));
        assert!(!cfg.bind_permitted(""));
    }
}
