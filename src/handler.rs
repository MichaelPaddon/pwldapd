/// Per-connection LDAP request handler.
use crate::config::{AttrValue, PROTECTED_ATTRS};
use crate::ber;
use crate::config::Config;
use crate::ldap::{
    self, LdapMessage, LdapOperation, LdapResult,
    SearchRequest, SearchResultEntry, Scope,
};
use crate::{passwd, pam_auth};
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

pub async fn handle_connection<S>(
    mut stream: S,
    config: Config,
    peer: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut bound_as: Option<String> = None;
    loop {
        let msg_bytes = match read_ldap_message(&mut stream).await {
            Ok(b) => b,
            Err(e)
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                debug!("Client disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let msg = match ldap::parse_message(&msg_bytes) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse LDAP message: {e}");
                // Best-effort: send protocolError using the message ID
                // from the raw bytes so the client knows the request failed.
                if let Some(id) = extract_message_id(&msg_bytes) {
                    let done = LdapMessage {
                        message_id: id,
                        operation: LdapOperation::SearchResultDone(
                            LdapResult::error(
                                ldap::PROTOCOL_ERROR,
                                "Protocol error",
                            ),
                        ),
                    };
                    let _ = stream
                        .write_all(&ldap::encode_message(&done))
                        .await;
                }
                return Ok(());
            }
        };
        let op = std::mem::discriminant(&msg.operation);
        debug!("{peer} id={} op={op:?}", msg.message_id);

        match msg.operation {
            LdapOperation::UnbindRequest => {
                debug!("UnbindRequest — closing");
                return Ok(());
            }
            LdapOperation::AbandonRequest(id) => {
                debug!("AbandonRequest for msg {id}");
            }
            LdapOperation::BindRequest(req) => {
                let (result, username) = do_bind(&req, &config, peer).await;
                bound_as = username;
                let resp = LdapMessage {
                    message_id: msg.message_id,
                    operation: LdapOperation::BindResponse(result),
                };
                stream.write_all(&ldap::encode_message(&resp)).await?;
            }
            LdapOperation::SearchRequest(req) => {
                let authorized = match &bound_as {
                    Some(u) => config.bind_permitted(u),
                    None    => config.require_bind.is_empty(),
                };
                do_search(&req, msg.message_id, &config, &mut stream, authorized).await?;
            }
            other => {
                warn!("Unhandled op: {:?}", std::mem::discriminant(&other));
            }
        }
    }
}

async fn do_bind(
    req: &ldap::BindRequest,
    config: &Config,
    peer: &str,
) -> (LdapResult, Option<String>) {
    let ldap::BindAuth::Simple(password) = &req.auth;
    if req.name.is_empty() && password.is_empty() {
        info!("{peer} anonymous bind");
        return (LdapResult::success(), None);
    }
    if password.is_empty() {
        info!("{peer} bind failed (empty password) dn={}", req.name);
        return (
            LdapResult::error(ldap::INVALID_CREDENTIALS, "Invalid credentials"),
            None,
        );
    }
    let username = uid_from_dn(&req.name)
        .unwrap_or(req.name.as_str())
        .to_string();
    let password = password.clone();
    let config = config.clone();
    let username_clone = username.clone();
    let ok = tokio::task::spawn_blocking(move || {
        if !pam_auth::authenticate(&username_clone, &password) {
            return false;
        }
        // Deny bind if the user's UID falls outside the configured range.
        // This keeps authentication consistent with what the directory serves.
        match passwd::get_user_by_name(&username_clone) {
            Some(u) => config.uid_allowed(u.uid),
            // Authenticated via PAM but no passwd entry; permit the bind.
            None => true,
        }
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!("PAM task panicked: {e}");
        false
    });
    if ok {
        info!("{peer} bind ok dn={}", req.name);
        (LdapResult::success(), Some(username))
    } else {
        info!("{peer} bind failed dn={}", req.name);
        (LdapResult::error(ldap::INVALID_CREDENTIALS, "Invalid credentials"), None)
    }
}

async fn do_search<S: AsyncWrite + Unpin>(
    req: &SearchRequest,
    message_id: i64,
    config: &Config,
    stream: &mut S,
    authorized: bool,
) -> Result<()> {
    if !authorized {
        let done = LdapMessage {
            message_id,
            operation: LdapOperation::SearchResultDone(LdapResult::error(
                ldap::INSUFFICIENT_ACCESS_RIGHTS,
                "Bind required",
            )),
        };
        stream.write_all(&ldap::encode_message(&done)).await?;
        return Ok(());
    }
    let req2 = req.clone();
    let config = config.clone();
    let entries = tokio::task::spawn_blocking(move || {
        collect_entries(&req2, &config)
    })
    .await?;

    for entry in &entries {
        if ldap::matches_filter(&req.filter, &entry.attributes) {
            let filtered = select_attributes(entry, &req.attributes);
            let msg = LdapMessage {
                message_id,
                operation: LdapOperation::SearchResultEntry(filtered),
            };
            stream.write_all(&ldap::encode_message(&msg)).await?;
        }
    }

    let done = LdapMessage {
        message_id,
        operation: LdapOperation::SearchResultDone(LdapResult::success()),
    };
    stream.write_all(&ldap::encode_message(&done)).await?;
    Ok(())
}

// Entry collection

fn collect_entries(
    req: &SearchRequest,
    config: &Config,
) -> Vec<SearchResultEntry> {
    let users: Vec<passwd::User> = passwd::get_all_users()
        .into_iter()
        .filter(|u| config.uid_allowed(u.uid))
        .collect();
    let primary_gids: std::collections::HashSet<u32> =
        users.iter().map(|u| u.gid).collect();
    let groups: Vec<passwd::Group> = passwd::get_all_groups()
        .into_iter()
        .filter(|g| {
            config.gid_allowed(g.gid) || primary_gids.contains(&g.gid)
        })
        .collect();
    collect_entries_from(req, config, &users, &groups)
}

/// Return all entries that satisfy the search *scope* (base DN + scope).
/// Filter evaluation is deliberately deferred to the caller (`do_search`)
/// so that this function can be tested independently of filter logic.
fn collect_entries_from(
    req: &SearchRequest,
    config: &Config,
    users: &[passwd::User],
    groups: &[passwd::Group],
) -> Vec<SearchResultEntry> {
    let base = req.base_dn.to_lowercase();
    let users_dn = config.users_dn().to_lowercase();
    let groups_dn = config.groups_dn().to_lowercase();
    let root_dn = config.base_dn.to_lowercase();

    let mut out = Vec::new();

    if base.is_empty() {
        if req.scope == Scope::Base {
            out.push(make_root_dse(config));
        }
        return out;
    }

    match req.scope {
        Scope::Base => {
            if base == root_dn {
                out.push(make_base_entry(config));
            } else if base == users_dn {
                out.push(make_ou_entry(&config.users_dn(), "people"));
            } else if base == groups_dn {
                out.push(make_ou_entry(&config.groups_dn(), "groups"));
            } else if let Some(uid) = leaf_attr(&base, "uid=", &users_dn) {
                if let Some(u) = users.iter()
                    .find(|u| u.name.eq_ignore_ascii_case(uid))
                {
                    out.push(user_entry(u, config));
                }
            } else if let Some(cn) = leaf_attr(&base, "cn=", &groups_dn)
                && let Some(g) = groups.iter()
                    .find(|g| g.name.eq_ignore_ascii_case(cn))
            {
                out.push(group_entry(g, config));
            }
        }
        Scope::OneLevel => {
            if base == root_dn {
                out.push(make_ou_entry(&config.users_dn(), "people"));
                out.push(make_ou_entry(&config.groups_dn(), "groups"));
            } else if base == users_dn {
                for u in users { out.push(user_entry(u, config)); }
            } else if base == groups_dn {
                for g in groups { out.push(group_entry(g, config)); }
            }
        }
        Scope::WholeSubtree => {
            if base == root_dn {
                out.push(make_base_entry(config));
                out.push(make_ou_entry(&config.users_dn(), "people"));
                out.push(make_ou_entry(&config.groups_dn(), "groups"));
                for u in users { out.push(user_entry(u, config)); }
                for g in groups { out.push(group_entry(g, config)); }
            } else if base == users_dn {
                out.push(make_ou_entry(&config.users_dn(), "people"));
                for u in users { out.push(user_entry(u, config)); }
            } else if base == groups_dn {
                out.push(make_ou_entry(&config.groups_dn(), "groups"));
                for g in groups { out.push(group_entry(g, config)); }
            } else if let Some(uid) = leaf_attr(&base, "uid=", &users_dn) {
                if let Some(u) = users.iter()
                    .find(|u| u.name.eq_ignore_ascii_case(uid))
                {
                    out.push(user_entry(u, config));
                }
            } else if let Some(cn) = leaf_attr(&base, "cn=", &groups_dn)
                && let Some(g) = groups.iter()
                    .find(|g| g.name.eq_ignore_ascii_case(cn))
            {
                out.push(group_entry(g, config));
            }
        }
    }

    out
}

// Entry constructors

fn make_root_dse(config: &Config) -> SearchResultEntry {
    SearchResultEntry {
        dn: String::new(),
        attributes: vec![
            ("objectClass".into(), vec!["top".into()]),
            ("namingContexts".into(), vec![config.base_dn.clone()]),
            ("supportedLDAPVersion".into(), vec!["3".into()]),
            ("vendorName".into(), vec!["pwldapd".into()]),
        ],
    }
}

fn make_base_entry(config: &Config) -> SearchResultEntry {
    let dc = config
        .base_dn
        .split(',')
        .find(|p| p.to_lowercase().starts_with("dc="))
        .map(|p| &p[3..])
        .unwrap_or("local");
    SearchResultEntry {
        dn: config.base_dn.clone(),
        attributes: vec![
            (
                "objectClass".into(),
                vec!["top".into(), "dcObject".into(), "organization".into()],
            ),
            ("dc".into(), vec![dc.into()]),
            ("o".into(), vec![dc.into()]),
        ],
    }
}

fn make_ou_entry(dn: &str, ou: &str) -> SearchResultEntry {
    SearchResultEntry {
        dn: dn.to_string(),
        attributes: vec![
            (
                "objectClass".into(),
                vec!["top".into(), "organizationalUnit".into()],
            ),
            ("ou".into(), vec![ou.into()]),
        ],
    }
}

fn user_entry(u: &passwd::User, config: &Config) -> SearchResultEntry {
    let dn = format!("uid={},{}", u.name, config.users_dn());

    let gecos_fields: Vec<&str> = u.gecos.splitn(5, ',')
        .map(str::trim)
        .collect();
    let gecos_field = |i: usize| -> Option<&str> {
        gecos_fields.get(i).copied().filter(|s| !s.is_empty())
    };

    let cn = gecos_field(0).unwrap_or(&u.name).to_string();
    let words: Vec<&str> = cn.split_whitespace().collect();
    let sn = words.last().copied().unwrap_or(&u.name).to_string();
    let given_name = if words.len() >= 2 {
        Some(words[0].to_string())
    } else {
        None
    };

    let mut attrs = vec![
        (
            "objectClass".into(),
            vec![
                "top".into(),
                "posixAccount".into(),
                "inetOrgPerson".into(),
            ],
        ),
        ("uid".into(), vec![u.name.clone()]),
        ("cn".into(), vec![cn.clone()]),
        ("sn".into(), vec![sn.clone()]),
        ("uidNumber".into(), vec![u.uid.to_string()]),
        ("gidNumber".into(), vec![u.gid.to_string()]),
        ("homeDirectory".into(), vec![u.home_dir.clone()]),
        ("loginShell".into(), vec![u.shell.clone()]),
        ("gecos".into(), vec![u.gecos.clone()]),
    ];
    if let Some(v) = given_name {
        attrs.push(("givenName".into(), vec![v]));
    }
    if let Some(v) = gecos_field(1) {
        attrs.push(("roomNumber".into(), vec![v.to_string()]));
    }
    if let Some(v) = gecos_field(2) {
        attrs.push(("telephoneNumber".into(), vec![v.to_string()]));
    }
    if let Some(v) = gecos_field(3) {
        attrs.push(("homePhone".into(), vec![v.to_string()]));
    }
    apply_user_attributes(&mut attrs, u, &cn, &sn, config);
    SearchResultEntry { dn, attributes: attrs }
}

fn group_entry(g: &passwd::Group, config: &Config) -> SearchResultEntry {
    let dn = format!("cn={},{}", g.name, config.groups_dn());
    let mut attrs = vec![
        ("objectClass".into(), vec!["top".into(), "posixGroup".into()]),
        ("cn".into(), vec![g.name.clone()]),
        ("gidNumber".into(), vec![g.gid.to_string()]),
    ];
    if !g.members.is_empty() {
        attrs.push(("memberUid".into(), g.members.clone()));
    }
    SearchResultEntry { dn, attributes: attrs }
}

// Attribute extension

/// Expand `{placeholder}` sequences in `template` using the given user fields.
/// All known placeholders are substituted; unrecognised ones are left as-is
/// (templates are validated at startup so this path is unreachable in practice).
fn expand_template(
    template: &str,
    user: &passwd::User,
    cn: &str,
    sn: &str,
) -> String {
    let uid_n = user.uid.to_string();
    let gid_n = user.gid.to_string();
    let vars: &[(&str, &str)] = &[
        ("uid",           &user.name),
        ("cn",            cn),
        ("sn",            sn),
        ("uidNumber",     &uid_n),
        ("gidNumber",     &gid_n),
        ("homeDirectory", &user.home_dir),
        ("shell",         &user.shell),
        ("gecos",         &user.gecos),
    ];
    let mut result = template.to_string();
    for (key, val) in vars {
        result = result.replace(&format!("{{{key}}}"), val);
    }
    result
}

/// Apply `config.user_attributes` and per-user overrides to an in-progress
/// attribute list. Called at the end of `user_entry()`.
///
/// Precedence (highest first):
///   1. `config.user_overrides[username][attr]` — fixed string
///   2. `config.user_attributes[attr]` — template or fixed string
///   3. Built-in attributes assembled earlier (may be replaced except for
///      protected attrs: objectClass, uid, uidNumber, gidNumber)
fn apply_user_attributes(
    attrs: &mut Vec<(String, Vec<String>)>,
    user: &passwd::User,
    cn: &str,
    sn: &str,
    config: &Config,
) {
    // Track which attribute names were handled via user_attributes so we
    // can skip them when processing the remaining per-user overrides.
    let mut handled: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for (attr_name, attr_val) in &config.user_attributes {
        if PROTECTED_ATTRS.iter().any(|p| p.eq_ignore_ascii_case(attr_name)) {
            continue;
        }
        handled.insert(attr_name.to_lowercase());

        // Resolve the value: check per-user override first, then the general rule.
        let value = if let Some(ov) = config.user_overrides
            .get(&user.name)
            .and_then(|m| m.get(attr_name))
        {
            ov.clone()
        } else {
            match attr_val {
                AttrValue::Fixed(s) => s.clone(),
                AttrValue::Template(t) => expand_template(t, user, cn, sn),
            }
        };

        // Replace an existing attribute or append a new one.
        if let Some(existing) = attrs.iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(attr_name))
        {
            existing.1 = vec![value];
        } else {
            attrs.push((attr_name.clone(), vec![value]));
        }
    }

    // Apply any per-user overrides whose keys were not covered by
    // user_attributes above.
    if let Some(overrides) = config.user_overrides.get(&user.name) {
        for (attr_name, value) in overrides {
            if handled.contains(&attr_name.to_lowercase()) {
                continue;
            }
            if PROTECTED_ATTRS.iter().any(|p| p.eq_ignore_ascii_case(attr_name)) {
                continue;
            }
            if let Some(existing) = attrs.iter_mut()
                .find(|(k, _)| k.eq_ignore_ascii_case(attr_name))
            {
                existing.1 = vec![value.clone()];
            } else {
                attrs.push((attr_name.clone(), vec![value.clone()]));
            }
        }
    }
}

// Helpers

/// If `dn` looks like `<prefix><value>,<parent_dn>`, return `<value>`.
fn leaf_attr<'a>(
    dn: &'a str,
    prefix: &str,
    parent_dn: &str,
) -> Option<&'a str> {
    let first = dn.split(',').next()?;
    let fl = first.to_lowercase();
    if !fl.starts_with(prefix) {
        return None;
    }
    let value = &first[prefix.len()..];
    let rest: String = dn.split_once(',')?.1.to_lowercase();
    if rest == parent_dn {
        Some(value)
    } else {
        None
    }
}

/// Extract the value of the first `uid=` component from a DN.
/// Used to obtain a plain username from a bind DN such as
/// `uid=alice,ou=people,dc=example,dc=com`.
fn uid_from_dn(dn: &str) -> Option<&str> {
    dn.split(',')
        .find(|p| p.to_lowercase().starts_with("uid="))
        .map(|p| &p[4..])
}

/// Filter an entry's attributes to only those listed in `requested`.
/// An empty list or a list containing `"*"` means return all attributes.
fn select_attributes(
    entry: &SearchResultEntry,
    requested: &[String],
) -> SearchResultEntry {
    if requested.is_empty() || requested.iter().any(|a| a == "*") {
        return entry.clone();
    }
    let lower: Vec<String> =
        requested.iter().map(|a| a.to_lowercase()).collect();
    let attributes = entry
        .attributes
        .iter()
        .filter(|(name, _)| lower.contains(&name.to_lowercase()))
        .cloned()
        .collect();
    SearchResultEntry { dn: entry.dn.clone(), attributes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::{Filter, Scope, SearchRequest};

    // Test fixtures

    fn cfg() -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            unix_listen: vec![],
            base_dn: "dc=example,dc=com".into(),
            uid_ranges: vec![],
            gid_ranges: vec![],
            tls_cert: None,
            tls_key: None,
            user_attributes: vec![],
            user_overrides: std::collections::HashMap::new(),
            require_bind: vec![],
        }
    }

    fn cfg_with_uid_ranges(
        ranges: Vec<std::ops::RangeInclusive<u32>>,
    ) -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            unix_listen: vec![],
            base_dn: "dc=example,dc=com".into(),
            uid_ranges: ranges,
            gid_ranges: vec![],
            tls_cert: None,
            tls_key: None,
            user_attributes: vec![],
            user_overrides: std::collections::HashMap::new(),
            require_bind: vec![],
        }
    }

    fn cfg_with_gid_ranges(
        ranges: Vec<std::ops::RangeInclusive<u32>>,
    ) -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            unix_listen: vec![],
            base_dn: "dc=example,dc=com".into(),
            uid_ranges: vec![],
            gid_ranges: ranges,
            tls_cert: None,
            tls_key: None,
            user_attributes: vec![],
            user_overrides: std::collections::HashMap::new(),
            require_bind: vec![],
        }
    }

    fn users() -> Vec<passwd::User> {
        vec![
            passwd::User {
                name: "alice".into(), uid: 1001, gid: 1001,
                gecos: "Alice Smith,,,".into(),
                home_dir: "/home/alice".into(),
                shell: "/bin/bash".into(),
            },
            passwd::User {
                name: "bob".into(), uid: 1002, gid: 1002,
                gecos: "Bob Jones".into(),
                home_dir: "/home/bob".into(),
                shell: "/bin/sh".into(),
            },
        ]
    }

    fn groups() -> Vec<passwd::Group> {
        vec![
            passwd::Group {
                name: "staff".into(), gid: 200,
                members: vec!["alice".into(), "bob".into()],
            },
            passwd::Group {
                name: "wheel".into(), gid: 201,
                members: vec!["alice".into()],
            },
            passwd::Group { name: "empty".into(), gid: 202, members: vec![] },
        ]
    }

    fn search(base: &str, scope: Scope, filter: Filter) -> SearchRequest {
        SearchRequest {
            base_dn: base.into(),
            scope,
            filter,
            attributes: vec![],
        }
    }

    fn dn_set(entries: &[SearchResultEntry]) -> Vec<String> {
        let mut dns: Vec<String> =
            entries.iter().map(|e| e.dn.clone()).collect();
        dns.sort();
        dns
    }

    fn attr_values<'a>(
        entry: &'a SearchResultEntry,
        name: &str,
    ) -> Vec<&'a str> {
        entry.attributes.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, vs)| vs.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    // Root DSE

    #[test]
    fn root_dse_base_scope() {
        let req = search(
            "", Scope::Base, Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "");
        let nc = attr_values(&entries[0], "namingContexts");
        assert!(nc.contains(&"dc=example,dc=com"));
    }

    #[test]
    fn root_dse_not_returned_for_one_level() {
        let req = search(
            "", Scope::OneLevel, Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert!(entries.is_empty());
    }

    // Base DN

    #[test]
    fn base_dn_base_scope() {
        let req = search(
            "dc=example,dc=com",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "dc=example,dc=com");
        assert!(attr_values(&entries[0], "objectClass").contains(&"dcObject"));
    }

    #[test]
    fn base_dn_case_insensitive() {
        let req = search(
            "DC=EXAMPLE,DC=COM",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn base_dn_one_level_returns_ous() {
        let req = search(
            "dc=example,dc=com",
            Scope::OneLevel,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        let dns = dn_set(&entries);
        assert_eq!(dns, vec![
            "ou=groups,dc=example,dc=com",
            "ou=people,dc=example,dc=com",
        ]);
    }

    #[test]
    fn base_dn_subtree_returns_everything() {
        let req = search(
            "dc=example,dc=com",
            Scope::WholeSubtree,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        // base + 2 OUs + 2 users + 3 groups = 8
        assert_eq!(entries.len(), 8);
    }

    // Users OU

    #[test]
    fn users_ou_base_scope() {
        let req = search(
            "ou=people,dc=example,dc=com",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "ou=people,dc=example,dc=com");
        let oc = attr_values(&entries[0], "objectClass");
        assert!(oc.contains(&"organizationalUnit"));
    }

    #[test]
    fn users_ou_one_level_returns_all_users() {
        let req = search(
            "ou=people,dc=example,dc=com",
            Scope::OneLevel,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        let dns = dn_set(&entries);
        assert_eq!(dns, vec![
            "uid=alice,ou=people,dc=example,dc=com",
            "uid=bob,ou=people,dc=example,dc=com",
        ]);
    }

    #[test]
    fn users_ou_subtree_includes_ou_entry() {
        let req = search(
            "ou=people,dc=example,dc=com",
            Scope::WholeSubtree,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 3); // OU + 2 users
        assert!(entries.iter().any(|e| e.dn == "ou=people,dc=example,dc=com"));
    }

    // Groups OU

    #[test]
    fn groups_ou_one_level_returns_all_groups() {
        let req = search(
            "ou=groups,dc=example,dc=com",
            Scope::OneLevel,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        let dns = dn_set(&entries);
        assert_eq!(dns, vec![
            "cn=empty,ou=groups,dc=example,dc=com",
            "cn=staff,ou=groups,dc=example,dc=com",
            "cn=wheel,ou=groups,dc=example,dc=com",
        ]);
    }

    // Specific entry lookups

    #[test]
    fn user_base_scope_by_dn() {
        let req = search(
            "uid=alice,ou=people,dc=example,dc=com",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "uid=alice,ou=people,dc=example,dc=com");
    }

    #[test]
    fn user_base_scope_nonexistent() {
        let req = search(
            "uid=nobody,ou=people,dc=example,dc=com",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert!(entries.is_empty());
    }

    #[test]
    fn group_base_scope_by_dn() {
        let req = search(
            "cn=staff,ou=groups,dc=example,dc=com",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dn, "cn=staff,ou=groups,dc=example,dc=com");
    }

    // Filter application

    #[test]
    fn search_filters_by_uid() {
        let req = SearchRequest {
            base_dn: "ou=people,dc=example,dc=com".into(),
            scope: Scope::OneLevel,
            filter: Filter::EqualityMatch {
                attr: "uid".into(),
                value: "alice".into(),
            },
            attributes: vec![],
        };
        // collect_entries_from returns candidates;
        // filter is applied in do_search.
        // Here we test it directly via matches_filter on the results.
        let all = collect_entries_from(&req, &cfg(), &users(), &groups());
        let filtered: Vec<_> = all.iter()
            .filter(|e| ldap::matches_filter(&req.filter, &e.attributes))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(attr_values(filtered[0], "uid"), vec!["alice"]);
    }

    // Entry construction

    #[test]
    fn user_entry_attributes() {
        let u = passwd::User {
            name: "alice".into(), uid: 1001, gid: 1001,
            gecos: "Alice Smith,,,".into(),
            home_dir: "/home/alice".into(), shell: "/bin/bash".into(),
        };
        let entry = user_entry(&u, &cfg());
        assert_eq!(entry.dn, "uid=alice,ou=people,dc=example,dc=com");
        assert_eq!(attr_values(&entry, "uid"), vec!["alice"]);
        assert_eq!(attr_values(&entry, "uidNumber"), vec!["1001"]);
        assert_eq!(attr_values(&entry, "gidNumber"), vec!["1001"]);
        assert_eq!(attr_values(&entry, "homeDirectory"), vec!["/home/alice"]);
        assert_eq!(attr_values(&entry, "loginShell"), vec!["/bin/bash"]);
        assert_eq!(attr_values(&entry, "cn"), vec!["Alice Smith"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["Smith"]);
        assert_eq!(attr_values(&entry, "givenName"), vec!["Alice"]);
        // empty gecos fields → no roomNumber/telephoneNumber/homePhone
        assert!(attr_values(&entry, "roomNumber").is_empty());
        assert!(attr_values(&entry, "telephoneNumber").is_empty());
        assert!(attr_values(&entry, "homePhone").is_empty());
        assert!(attr_values(&entry, "objectClass").contains(&"posixAccount"));
        assert!(attr_values(&entry, "objectClass").contains(&"inetOrgPerson"));
    }

    #[test]
    fn user_entry_full_gecos() {
        let u = passwd::User {
            name: "bob".into(), uid: 1002, gid: 1002,
            gecos: "Bob Jones,Room 42,+1-555-0100,+1-555-0101,extra".into(),
            home_dir: "/home/bob".into(), shell: "/bin/sh".into(),
        };
        let entry = user_entry(&u, &cfg());
        assert_eq!(attr_values(&entry, "cn"), vec!["Bob Jones"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["Jones"]);
        assert_eq!(attr_values(&entry, "givenName"), vec!["Bob"]);
        assert_eq!(attr_values(&entry, "roomNumber"), vec!["Room 42"]);
        assert_eq!(
            attr_values(&entry, "telephoneNumber"), vec!["+1-555-0100"],
        );
        assert_eq!(attr_values(&entry, "homePhone"), vec!["+1-555-0101"]);
    }

    #[test]
    fn user_entry_single_name_no_given_name() {
        let u = passwd::User {
            name: "root".into(), uid: 0, gid: 0,
            gecos: "root".into(),
            home_dir: "/root".into(), shell: "/bin/bash".into(),
        };
        let entry = user_entry(&u, &cfg());
        assert_eq!(attr_values(&entry, "cn"), vec!["root"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["root"]);
        assert!(attr_values(&entry, "givenName").is_empty());
    }

    #[test]
    fn user_entry_empty_gecos_uses_name() {
        let u = passwd::User {
            name: "daemon".into(), uid: 1, gid: 1,
            gecos: "".into(),
            home_dir: "/".into(), shell: "/usr/sbin/nologin".into(),
        };
        let entry = user_entry(&u, &cfg());
        assert_eq!(attr_values(&entry, "cn"), vec!["daemon"]);
        assert_eq!(attr_values(&entry, "sn"), vec!["daemon"]);
        assert!(attr_values(&entry, "givenName").is_empty());
    }

    #[test]
    fn group_entry_with_members() {
        let g = passwd::Group {
            name: "staff".into(), gid: 200,
            members: vec!["alice".into(), "bob".into()],
        };
        let entry = group_entry(&g, &cfg());
        assert_eq!(entry.dn, "cn=staff,ou=groups,dc=example,dc=com");
        assert_eq!(attr_values(&entry, "cn"), vec!["staff"]);
        assert_eq!(attr_values(&entry, "gidNumber"), vec!["200"]);
        let mut members = attr_values(&entry, "memberUid");
        members.sort();
        assert_eq!(members, vec!["alice", "bob"]);
        assert!(attr_values(&entry, "objectClass").contains(&"posixGroup"));
    }

    #[test]
    fn group_entry_no_members_omits_memberuid() {
        let g = passwd::Group {
            name: "empty".into(), gid: 202, members: vec![],
        };
        let entry = group_entry(&g, &cfg());
        assert!(attr_values(&entry, "memberUid").is_empty());
    }

    // UID range filtering

    fn filtered_users(
        ranges: Vec<std::ops::RangeInclusive<u32>>,
    ) -> Vec<passwd::User> {
        let cfg = cfg_with_uid_ranges(ranges);
        users().into_iter().filter(|u| cfg.uid_allowed(u.uid)).collect()
    }

    #[test]
    fn uid_range_excludes_users_outside_range() {
        // alice=1001, bob=1002; only include 1001-1001
        let subset = filtered_users(vec![1001..=1001]);
        assert_eq!(subset.len(), 1);
        assert_eq!(subset[0].name, "alice");
    }

    #[test]
    fn uid_range_includes_all_in_range() {
        let subset = filtered_users(vec![1001..=1002]);
        assert_eq!(subset.len(), 2);
    }

    #[test]
    fn uid_range_empty_range_excludes_all() {
        let subset = filtered_users(vec![5000..=6000]);
        assert!(subset.is_empty());
    }

    #[test]
    fn uid_range_multiple_ranges() {
        let subset = filtered_users(vec![1001..=1001, 1002..=1002]);
        assert_eq!(subset.len(), 2);
    }

    #[test]
    fn uid_filtered_search_returns_only_allowed_users() {
        let cfg = cfg_with_uid_ranges(vec![1001..=1001]);
        let allowed: Vec<passwd::User> = users()
            .into_iter()
            .filter(|u| cfg.uid_allowed(u.uid))
            .collect();
        let req = search(
            "ou=people,dc=example,dc=com",
            Scope::OneLevel,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg, &allowed, &groups());
        let dns = dn_set(&entries);
        assert_eq!(dns, vec!["uid=alice,ou=people,dc=example,dc=com"]);
    }

    #[test]
    fn uid_filtered_base_scope_excluded_user_returns_empty() {
        let cfg = cfg_with_uid_ranges(vec![1002..=1002]); // bob only
        let allowed: Vec<passwd::User> = users()
            .into_iter()
            .filter(|u| cfg.uid_allowed(u.uid))
            .collect();
        // direct DN lookup for alice — should return nothing
        // since she's filtered out
        let req = search(
            "uid=alice,ou=people,dc=example,dc=com",
            Scope::Base,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg, &allowed, &groups());
        assert!(entries.is_empty());
    }

    // GID range filtering

    fn filtered_groups_with_primary(
        gid_ranges: Vec<std::ops::RangeInclusive<u32>>,
        served_users: &[passwd::User],
    ) -> Vec<passwd::Group> {
        let cfg = cfg_with_gid_ranges(gid_ranges);
        let primary_gids: std::collections::HashSet<u32> =
            served_users.iter().map(|u| u.gid).collect();
        groups()
            .into_iter()
            .filter(|g| {
                cfg.gid_allowed(g.gid) || primary_gids.contains(&g.gid)
            })
            .collect()
    }

    #[test]
    fn gid_range_no_ranges_permits_all_groups() {
        // gid_ranges empty → all groups served
        let subset = filtered_groups_with_primary(vec![], &users());
        assert_eq!(subset.len(), groups().len());
    }

    #[test]
    fn gid_range_restricts_groups() {
        // staff=200, wheel=201, empty=202; alice.gid=1001, bob.gid=1002
        // Restrict to 202-202: only "empty" is in range.
        // Primary GIDs 1001,1002 have no matching group in test data.
        let subset =
            filtered_groups_with_primary(vec![202..=202], &users());
        assert_eq!(subset.len(), 1);
        assert_eq!(subset[0].name, "empty");
    }

    #[test]
    fn primary_gid_always_visible() {
        // alice has gid=1001, bob has gid=1002.
        // Neither 1001 nor 1002 is in groups(), so no extra entries.
        // But if we add a group with gid=1001, it must appear even when
        // gid_ranges excludes it.
        let mut all_groups = groups(); // gids 200,201,202
        all_groups.push(passwd::Group {
            name: "alicegroup".into(),
            gid: 1001,
            members: vec![],
        });
        let cfg = cfg_with_gid_ranges(vec![200..=200]); // only staff
        let primary_gids: std::collections::HashSet<u32> =
            users().iter().map(|u| u.gid).collect();
        let visible: Vec<&passwd::Group> = all_groups
            .iter()
            .filter(|g| {
                cfg.gid_allowed(g.gid) || primary_gids.contains(&g.gid)
            })
            .collect();
        // staff (200 in range) + alicegroup (1001 is alice's primary GID)
        let names: Vec<&str> =
            visible.iter().map(|g| g.name.as_str()).collect();
        assert!(names.contains(&"staff"));
        assert!(names.contains(&"alicegroup"));
        assert!(!names.contains(&"wheel"));
        assert!(!names.contains(&"empty"));
    }

    #[test]
    fn gid_filtered_search_returns_only_allowed_groups() {
        let cfg = cfg_with_gid_ranges(vec![200..=200]); // only staff
        let primary_gids: std::collections::HashSet<u32> =
            users().iter().map(|u| u.gid).collect();
        let allowed_groups: Vec<passwd::Group> = groups()
            .into_iter()
            .filter(|g| {
                cfg.gid_allowed(g.gid) || primary_gids.contains(&g.gid)
            })
            .collect();
        let req = search(
            "ou=groups,dc=example,dc=com",
            Scope::OneLevel,
            Filter::Present("objectClass".into()),
        );
        let entries =
            collect_entries_from(&req, &cfg, &users(), &allowed_groups);
        let dns = dn_set(&entries);
        assert_eq!(dns, vec!["cn=staff,ou=groups,dc=example,dc=com"]);
    }

    // Attribute selection

    #[test]
    fn select_all_when_empty_requested() {
        let u = &users()[0];
        let entry = user_entry(u, &cfg());
        let selected = select_attributes(&entry, &[]);
        assert_eq!(selected.attributes.len(), entry.attributes.len());
    }

    #[test]
    fn select_specific_attributes() {
        let u = &users()[0];
        let entry = user_entry(u, &cfg());
        let requested: Vec<String> = vec!["uid".into(), "uidNumber".into()];
        let selected = select_attributes(&entry, &requested);
        assert_eq!(selected.attributes.len(), 2);
        assert!(attr_values(&selected, "uid").contains(&"alice"));
        assert!(attr_values(&selected, "cn").is_empty());
    }

    #[test]
    fn select_star_returns_all() {
        let u = &users()[0];
        let entry = user_entry(u, &cfg());
        let selected = select_attributes(&entry, &["*".into()]);
        assert_eq!(selected.attributes.len(), entry.attributes.len());
    }

    // User attribute extension

    fn alice() -> passwd::User {
        passwd::User {
            name: "alice".into(), uid: 1001, gid: 1001,
            gecos: "Alice Smith,,,".into(),
            home_dir: "/home/alice".into(),
            shell: "/bin/bash".into(),
        }
    }

    fn cfg_with_user_attrs(
        attrs: Vec<(String, crate::config::AttrValue)>,
        overrides: std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    ) -> Config {
        Config {
            listen: vec![],
            tls_listen: vec![],
            unix_listen: vec![],
            base_dn: "dc=example,dc=com".into(),
            uid_ranges: vec![],
            gid_ranges: vec![],
            tls_cert: None,
            tls_key: None,
            user_attributes: attrs,
            user_overrides: overrides,
            require_bind: vec![],
        }
    }

    #[test]
    fn template_attr_expands_uid() {
        let cfg = cfg_with_user_attrs(
            vec![(
                "mail".into(),
                crate::config::AttrValue::Template("{uid}@example.com".into()),
            )],
            std::collections::HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "mail"), vec!["alice@example.com"]);
    }

    #[test]
    fn fixed_attr_added() {
        let cfg = cfg_with_user_attrs(
            vec![(
                "department".into(),
                crate::config::AttrValue::Fixed("Engineering".into()),
            )],
            std::collections::HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "department"), vec!["Engineering"]);
    }

    #[test]
    fn user_attr_overrides_builtin() {
        let cfg = cfg_with_user_attrs(
            vec![(
                "loginShell".into(),
                crate::config::AttrValue::Fixed("/bin/zsh".into()),
            )],
            std::collections::HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "loginShell"), vec!["/bin/zsh"]);
    }

    #[test]
    fn per_user_override_takes_precedence() {
        let mut overrides = std::collections::HashMap::new();
        let mut alice_ov = std::collections::HashMap::new();
        alice_ov.insert("mail".into(), "alice@external.com".into());
        overrides.insert("alice".into(), alice_ov);
        let cfg = cfg_with_user_attrs(
            vec![(
                "mail".into(),
                crate::config::AttrValue::Template("{uid}@example.com".into()),
            )],
            overrides,
        );
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "mail"), vec!["alice@external.com"]);
    }

    #[test]
    fn per_user_override_without_general_rule() {
        let mut overrides = std::collections::HashMap::new();
        let mut alice_ov = std::collections::HashMap::new();
        alice_ov.insert("title".into(), "Director".into());
        overrides.insert("alice".into(), alice_ov);
        let cfg = cfg_with_user_attrs(vec![], overrides);
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "title"), vec!["Director"]);
    }

    #[test]
    fn override_for_other_user_not_applied() {
        let mut overrides = std::collections::HashMap::new();
        let mut bob_ov = std::collections::HashMap::new();
        bob_ov.insert("mail".into(), "bob@other.com".into());
        overrides.insert("bob".into(), bob_ov);
        let cfg = cfg_with_user_attrs(
            vec![(
                "mail".into(),
                crate::config::AttrValue::Template("{uid}@example.com".into()),
            )],
            overrides,
        );
        // alice gets the template value, not bob's override
        let entry = user_entry(&alice(), &cfg);
        assert_eq!(attr_values(&entry, "mail"), vec!["alice@example.com"]);
    }

    // do_search authorization

    /// Minimal AsyncWrite that accumulates bytes in a Vec.
    struct CaptureBuf(Vec<u8>);

    impl tokio::io::AsyncWrite for CaptureBuf {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn any_search() -> SearchRequest {
        search(
            "dc=example,dc=com",
            Scope::WholeSubtree,
            Filter::Present("objectClass".into()),
        )
    }

    /// Decode the last LDAP message in `buf` and return `(message_id, result_code)`.
    /// Walks through all complete messages (each is an outer SEQUENCE TLV) and
    /// returns the operation tag and result code of the final one.
    /// Panics unless the final message is a SearchResultDone (tag 0x65).
    fn parse_last_search_result_done(buf: &[u8]) -> (i64, u32) {
        const APP_SEARCH_RESULT_DONE: u8 = 0x65;
        let mut remaining = buf;
        let mut last = None;
        while !remaining.is_empty() {
            let (seq, rest) = ber::expect_tag(remaining, ber::TAG_SEQUENCE)
                .expect("outer SEQUENCE");
            // Determine how many bytes the entire TLV consumed.
            let consumed = remaining.len() - rest.len();
            remaining = rest;

            let (message_id, op_bytes) = ber::decode_integer(seq).expect("message_id");
            let (op_tag, op_value, _) = ber::parse_tlv(op_bytes).expect("operation TLV");
            last = Some((consumed, message_id, op_tag, op_value.to_vec()));
        }
        let (_, message_id, op_tag, op_value) = last.expect("no messages in buffer");
        assert_eq!(op_tag, APP_SEARCH_RESULT_DONE, "expected SearchResultDone");
        let (result_code, _) = ber::decode_enumerated(&op_value).expect("result_code");
        (message_id, result_code)
    }

    #[tokio::test]
    async fn unauthorized_search_returns_insufficient_access_rights() {
        let mut buf = CaptureBuf(vec![]);
        do_search(&any_search(), 7, &cfg(), &mut buf, false)
            .await
            .unwrap();

        let (message_id, result_code) = parse_last_search_result_done(&buf.0);
        assert_eq!(message_id, 7);
        assert_eq!(result_code, ldap::INSUFFICIENT_ACCESS_RIGHTS);
    }

    #[tokio::test]
    async fn authorized_search_returns_success() {
        // Use a base DN that does not match the config so collect_entries_from
        // returns nothing, giving us exactly one message: SearchResultDone.
        let req = search(
            "dc=nonexistent,dc=invalid",
            Scope::WholeSubtree,
            Filter::Present("objectClass".into()),
        );
        let mut buf = CaptureBuf(vec![]);
        do_search(&req, 3, &cfg(), &mut buf, true).await.unwrap();

        let (message_id, result_code) = parse_last_search_result_done(&buf.0);
        assert_eq!(message_id, 3);
        assert_eq!(result_code, ldap::SUCCESS);
    }

    // uid_from_dn

    #[test]
    fn uid_from_dn_extracts_from_full_dn() {
        assert_eq!(
            uid_from_dn("uid=alice,ou=people,dc=example,dc=com"),
            Some("alice"),
        );
    }

    #[test]
    fn uid_from_dn_handles_no_uid_component() {
        assert_eq!(
            uid_from_dn("cn=staff,ou=groups,dc=example,dc=com"),
            None,
        );
        assert_eq!(uid_from_dn(""), None);
    }

    #[test]
    fn uid_from_dn_bare_username_no_dn() {
        // Some clients send just "alice" as the bind DN.
        // uid_from_dn won't find a uid= component; the caller falls back
        // to the raw name.
        assert_eq!(uid_from_dn("alice"), None);
    }

    // select_attributes

    #[test]
    fn select_attributes_case_insensitive_names() {
        let u = &users()[0];
        let entry = user_entry(u, &cfg());
        // Request attribute name in a different case from what's stored.
        let selected = select_attributes(&entry, &["UID".into(), "CN".into()]);
        assert_eq!(selected.attributes.len(), 2);
        assert!(attr_values(&selected, "uid").contains(&"alice"));
        assert!(attr_values(&selected, "cn").contains(&"Alice Smith"));
    }

    // GECOS three-word name

    #[test]
    fn user_entry_three_word_name() {
        let u = passwd::User {
            name: "jsmith".into(), uid: 1003, gid: 1003,
            gecos: "John Paul Smith".into(),
            home_dir: "/home/jsmith".into(),
            shell: "/bin/bash".into(),
        };
        let entry = user_entry(&u, &cfg());
        assert_eq!(attr_values(&entry, "cn"),        vec!["John Paul Smith"]);
        assert_eq!(attr_values(&entry, "sn"),        vec!["Smith"]);
        assert_eq!(attr_values(&entry, "givenName"), vec!["John"]);
    }

    // Unrecognised base DN

    #[test]
    fn unrecognized_base_dn_returns_empty() {
        let req = search(
            "dc=unrelated,dc=org",
            Scope::WholeSubtree,
            Filter::Present("objectClass".into()),
        );
        let entries = collect_entries_from(&req, &cfg(), &users(), &groups());
        assert!(entries.is_empty());
    }

    #[test]
    fn protected_attr_not_overridden() {
        let cfg = cfg_with_user_attrs(
            vec![(
                "objectClass".into(),
                crate::config::AttrValue::Fixed("hacker".into()),
            )],
            std::collections::HashMap::new(),
        );
        let entry = user_entry(&alice(), &cfg);
        // objectClass must still contain the standard values
        let oc = attr_values(&entry, "objectClass");
        assert!(oc.contains(&"posixAccount"));
        assert!(!oc.contains(&"hacker"));
    }
}

// Wire reading

/// Extract the message ID from raw BER bytes without a full parse.
/// Used to send a protocolError response when full parsing fails.
fn extract_message_id(buf: &[u8]) -> Option<i64> {
    let (seq, _) = ber::expect_tag(buf, ber::TAG_SEQUENCE).ok()?;
    let (id, _) = ber::decode_integer(seq).ok()?;
    Some(id)
}

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

async fn read_ldap_message<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await?;

    let mut first_len = [0u8; 1];
    stream.read_exact(&mut first_len).await?;

    let mut header = vec![tag[0], first_len[0]];

    let content_len = if first_len[0] & 0x80 == 0 {
        first_len[0] as usize
    } else {
        let n = (first_len[0] & 0x7f) as usize;
        let mut extra = vec![0u8; n];
        stream.read_exact(&mut extra).await?;
        header.extend_from_slice(&extra);
        let mut len = 0usize;
        for b in &extra {
            len = (len << 8) | *b as usize;
        }
        len
    };

    if content_len > MAX_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("LDAP message too large ({content_len} bytes)"),
        ));
    }

    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;
    header.extend_from_slice(&content);
    Ok(Zeroizing::new(header))
}
