/// LDAP protocol types, parser, encoder, and filter evaluator.
use crate::ber::{self, BerError, BerResult};

// Result codes
pub const SUCCESS: u32 = 0;
pub const PROTOCOL_ERROR: u32 = 2;
pub const INVALID_CREDENTIALS: u32 = 49;

// Application tags
const APP_BIND_REQUEST: u8 = 0x60;
const APP_BIND_RESPONSE: u8 = 0x61;
const APP_UNBIND_REQUEST: u8 = 0x42;
const APP_SEARCH_REQUEST: u8 = 0x63;
const APP_SEARCH_RESULT_ENTRY: u8 = 0x64;
const APP_SEARCH_RESULT_DONE: u8 = 0x65;
const APP_ABANDON_REQUEST: u8 = 0x70;

// simple auth is context [0] primitive
const CTX_SIMPLE_AUTH: u8 = 0x80;

// Types

#[derive(Debug, Clone)]
pub struct LdapMessage {
    pub message_id: i64,
    pub operation: LdapOperation,
}

#[derive(Debug, Clone)]
pub enum LdapOperation {
    BindRequest(BindRequest),
    BindResponse(LdapResult),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
    AbandonRequest(i64),
}

#[derive(Debug, Clone)]
pub struct LdapResult {
    pub result_code: u32,
    pub matched_dn: String,
    pub diagnostic_message: String,
}

impl LdapResult {
    pub fn success() -> Self {
        Self {
            result_code: SUCCESS,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
        }
    }
    pub fn error(code: u32, msg: impl Into<String>) -> Self {
        Self {
            result_code: code,
            matched_dn: String::new(),
            diagnostic_message: msg.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BindAuth {
    Simple(String),
}

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub name: String,
    pub auth: BindAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base = 0,
    OneLevel = 1,
    WholeSubtree = 2,
}

#[derive(Debug, Clone)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch { attr: String, value: String },
    Substrings {
        attr: String,
        initial: Option<String>,
        any: Vec<String>,
        final_: Option<String>,
    },
    GreaterOrEqual,
    LessOrEqual,
    Present(String),
    ApproxMatch,
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub base_dn: String,
    pub scope: Scope,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

// Parsing

/// Parse a complete LDAP message from a BER-encoded buffer.
/// The buffer must contain exactly one top-level SEQUENCE with a message ID
/// followed by a protocol operation. Trailing bytes are ignored.
pub fn parse_message(buf: &[u8]) -> BerResult<LdapMessage> {
    let (seq, _) = ber::expect_tag(buf, ber::TAG_SEQUENCE)?;
    let (message_id, rest) = ber::decode_integer(seq)?;
    if rest.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let op_tag = rest[0];
    let (op_value, _) = ber::parse_tlv(rest).map(|(_, v, r)| (v, r))?;

    let operation = match op_tag {
        APP_BIND_REQUEST => LdapOperation::BindRequest(
            parse_bind_request(op_value)?,
        ),
        APP_UNBIND_REQUEST => LdapOperation::UnbindRequest,
        APP_SEARCH_REQUEST => LdapOperation::SearchRequest(
            parse_search_request(op_value)?,
        ),
        APP_ABANDON_REQUEST => {
            let mut id = 0i64;
            for b in op_value { id = (id << 8) | *b as i64; }
            LdapOperation::AbandonRequest(id)
        }
        tag => {
            tracing::warn!("Unsupported LDAP operation tag {tag:#04x}");
            return Err(BerError::UnexpectedTag { expected: 0, got: tag });
        }
    };

    Ok(LdapMessage { message_id, operation })
}

fn parse_bind_request(buf: &[u8]) -> BerResult<BindRequest> {
    let (_, rest) = ber::decode_integer(buf)?; // version: not used
    let (name, rest) = ber::decode_string(rest)?;
    if rest.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let auth_tag = rest[0];
    let (auth_value, _) = ber::parse_tlv(rest).map(|(_, v, r)| (v, r))?;
    let auth = match auth_tag {
        CTX_SIMPLE_AUTH => {
            let pw = String::from_utf8(auth_value.to_vec())
                .map_err(|_| BerError::InvalidUtf8)?;
            BindAuth::Simple(pw)
        }
        _ => BindAuth::Simple(String::new()),
    };
    Ok(BindRequest { name, auth })
}

fn parse_search_request(buf: &[u8]) -> BerResult<SearchRequest> {
    let (base_dn, rest) = ber::decode_string(buf)?;
    let (scope_val, rest) = ber::decode_enumerated(rest)?;
    let (_, rest) = ber::decode_enumerated(rest)?; // derefAliases: not used
    let (_, rest) = ber::decode_integer(rest)?;    // sizeLimit: not used
    let (_, rest) = ber::decode_integer(rest)?;    // timeLimit: not used
    let (_, rest) = ber::decode_boolean(rest)?;    // typesOnly: not used
    let (filter, rest) = parse_filter(rest, 0)?;

    let mut attributes = Vec::new();
    if !rest.is_empty() {
        let (attrs_seq, _) = ber::expect_tag(rest, ber::TAG_SEQUENCE)?;
        let mut r = attrs_seq;
        while !r.is_empty() {
            let (attr, next) = ber::decode_string(r)?;
            attributes.push(attr);
            r = next;
        }
    }

    let scope = match scope_val {
        0 => Scope::Base,
        1 => Scope::OneLevel,
        _ => Scope::WholeSubtree,
    };

    Ok(SearchRequest { base_dn, scope, filter, attributes })
}

const MAX_FILTER_DEPTH: u32 = 32;

fn parse_filter(buf: &[u8], depth: u32) -> BerResult<(Filter, &[u8])> {
    if depth > MAX_FILTER_DEPTH {
        return Err(BerError::NestingTooDeep);
    }
    if buf.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let tag = buf[0];
    let (value, rest) = ber::parse_tlv(buf).map(|(_, v, r)| (v, r))?;

    let filter = match tag {
        0xa0 => Filter::And(parse_filter_list(value, depth + 1)?),
        0xa1 => Filter::Or(parse_filter_list(value, depth + 1)?),
        0xa2 => {
            let (inner, _) = parse_filter(value, depth + 1)?;
            Filter::Not(Box::new(inner))
        }
        0xa3 => {
            let (attr, v) = ber::decode_string(value)?;
            let (val, _) = ber::decode_string(v)?;
            Filter::EqualityMatch { attr, value: val }
        }
        0xa4 => parse_substrings(value)?,
        0xa5 => Filter::GreaterOrEqual,
        0xa6 => Filter::LessOrEqual,
        0x87 => {
            let attr = String::from_utf8(value.to_vec())
                .map_err(|_| BerError::InvalidUtf8)?;
            Filter::Present(attr)
        }
        0xa8 => Filter::ApproxMatch,
        _ => {
            tracing::warn!("Unknown filter tag {tag:#04x}");
            return Err(BerError::UnexpectedTag { expected: 0, got: tag });
        }
    };
    Ok((filter, rest))
}

fn parse_filter_list(buf: &[u8], depth: u32) -> BerResult<Vec<Filter>> {
    let mut filters = Vec::new();
    let mut r = buf;
    while !r.is_empty() {
        let (f, next) = parse_filter(r, depth)?;
        filters.push(f);
        r = next;
    }
    Ok(filters)
}

fn parse_substrings(buf: &[u8]) -> BerResult<Filter> {
    let (attr, rest) = ber::decode_string(buf)?;
    let (subs_seq, _) = ber::expect_tag(rest, ber::TAG_SEQUENCE)?;
    let mut initial = None;
    let mut any = Vec::new();
    let mut final_ = None;
    let mut r = subs_seq;
    while !r.is_empty() {
        let sub_tag = r[0];
        let (sub_val, next) = ber::parse_tlv(r).map(|(_, v, n)| (v, n))?;
        let s = String::from_utf8(sub_val.to_vec())
            .map_err(|_| BerError::InvalidUtf8)?;
        match sub_tag {
            0x80 => initial = Some(s),
            0x81 => any.push(s),
            0x82 => final_ = Some(s),
            _ => {}
        }
        r = next;
    }
    Ok(Filter::Substrings { attr, initial, any, final_ })
}

// Encoding

/// Encode an LDAP message as a BER SEQUENCE. Only response-type operations
/// (BindResponse, SearchResultEntry, SearchResultDone) are supported; calling
/// this with a request-type operation will panic.
pub fn encode_message(msg: &LdapMessage) -> Vec<u8> {
    let mut content = ber::encode_integer(msg.message_id);
    content.extend(encode_operation(&msg.operation));
    ber::encode_tlv(ber::TAG_SEQUENCE, &content)
}

fn encode_operation(op: &LdapOperation) -> Vec<u8> {
    match op {
        LdapOperation::BindResponse(r) =>
            encode_ldap_result(APP_BIND_RESPONSE, r),
        LdapOperation::SearchResultEntry(e) =>
            encode_search_result_entry(e),
        LdapOperation::SearchResultDone(r) =>
            encode_ldap_result(APP_SEARCH_RESULT_DONE, r),
        _ => unreachable!("encode_operation called with a request-type operation"),
    }
}

fn encode_ldap_result(tag: u8, r: &LdapResult) -> Vec<u8> {
    let mut content = ber::encode_enumerated(r.result_code);
    content.extend(ber::encode_string(&r.matched_dn));
    content.extend(ber::encode_string(&r.diagnostic_message));
    ber::encode_tlv(tag, &content)
}

fn encode_search_result_entry(entry: &SearchResultEntry) -> Vec<u8> {
    let mut content = ber::encode_string(&entry.dn);
    let mut attrs_content = Vec::new();
    for (name, values) in &entry.attributes {
        let vals: Vec<Vec<u8>> = values
            .iter()
            .map(|v| ber::encode_string(v))
            .collect();
        let mut attr_seq = ber::encode_string(name);
        attr_seq.extend(ber::encode_set(&vals));
        attrs_content.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &attr_seq));
    }
    content.extend(ber::encode_tlv(ber::TAG_SEQUENCE, &attrs_content));
    ber::encode_tlv(APP_SEARCH_RESULT_ENTRY, &content)
}

// Filter evaluation

/// Evaluate a parsed LDAP filter against a set of entry attributes.
/// All string comparisons are case-insensitive. `objectClass` is treated
/// as always present regardless of the stored attribute list.
pub fn matches_filter(
    filter: &Filter,
    attrs: &[(String, Vec<String>)],
) -> bool {
    match filter {
        Filter::Present(attr) => {
            let al = attr.to_lowercase();
            al == "objectclass"
                || attrs.iter().any(|(a, _)| a.to_lowercase() == al)
        }
        Filter::EqualityMatch { attr, value } => {
            let al = attr.to_lowercase();
            let vl = value.to_lowercase();
            attrs.iter().any(|(a, vals)| {
                a.to_lowercase() == al
                    && vals.iter().any(|v| v.to_lowercase() == vl)
            })
        }
        Filter::And(filters) =>
            filters.iter().all(|f| matches_filter(f, attrs)),
        Filter::Or(filters) =>
            filters.iter().any(|f| matches_filter(f, attrs)),
        Filter::Not(f) => !matches_filter(f, attrs),
        Filter::Substrings { attr, initial, any, final_ } => {
            let al = attr.to_lowercase();
            attrs.iter().any(|(a, vals)| {
                a.to_lowercase() == al
                    && vals.iter().any(|v| {
                        let vl = v.to_lowercase();
                        let after_init = if let Some(i) = initial {
                            let il = i.to_lowercase();
                            if !vl.starts_with(&il) { return false; }
                            vl[il.len()..].to_string()
                        } else {
                            vl.clone()
                        };
                        let after_any = any.iter().try_fold(
                            after_init,
                            |s, sub| {
                                let sl = sub.to_lowercase();
                                s.find(&sl)
                                    .map(|i| s[i + sl.len()..].to_string())
                            },
                        );
                        match after_any {
                            None => false,
                            Some(rem) => match final_ {
                                Some(fin) => rem.ends_with(&fin.to_lowercase()),
                                None => true,
                            },
                        }
                    })
            })
        }
        // Ordering and approx match not needed for typical directory queries
        Filter::GreaterOrEqual
        | Filter::LessOrEqual
        | Filter::ApproxMatch => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber;

    // Helpers

    fn attrs(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(k, vs)| {
                (k.to_string(), vs.iter().map(|v| v.to_string()).collect())
            })
            .collect()
    }

    fn eq(attr: &str, value: &str) -> Filter {
        Filter::EqualityMatch { attr: attr.into(), value: value.into() }
    }

    // Filter: present

    #[test]
    fn filter_present_objectclass_always_matches() {
        // objectClass is synthetic — always present regardless of stored attrs
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&Filter::Present("objectClass".into()), &a));
        assert!(matches_filter(&Filter::Present("OBJECTCLASS".into()), &a));
    }

    #[test]
    fn filter_present_existing_attr() {
        let a = attrs(&[("uid", &["alice"]), ("cn", &["Alice Smith"])]);
        assert!(matches_filter(&Filter::Present("uid".into()), &a));
        assert!(matches_filter(&Filter::Present("cn".into()), &a));
    }

    #[test]
    fn filter_present_missing_attr() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&Filter::Present("mail".into()), &a));
    }

    // Filter: equality

    #[test]
    fn filter_equality_match() {
        let a = attrs(&[("uid", &["alice"]), ("cn", &["Alice Smith"])]);
        assert!(matches_filter(&eq("uid", "alice"), &a));
        assert!(!matches_filter(&eq("uid", "bob"), &a));
    }

    #[test]
    fn filter_equality_case_insensitive_attr_name() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&eq("UID", "alice"), &a));
        assert!(matches_filter(&eq("Uid", "alice"), &a));
    }

    #[test]
    fn filter_equality_case_insensitive_value() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&eq("uid", "Alice"), &a));
        assert!(matches_filter(&eq("uid", "ALICE"), &a));
    }

    #[test]
    fn filter_equality_multi_value_attr() {
        let a = attrs(&[("objectClass",
            &["top", "posixAccount", "inetOrgPerson"])]);
        assert!(matches_filter(&eq("objectClass", "posixAccount"), &a));
        assert!(matches_filter(&eq("objectClass", "top"), &a));
        assert!(!matches_filter(&eq("objectClass", "posixGroup"), &a));
    }

    // Filter: AND / OR / NOT

    #[test]
    fn filter_empty_and_is_vacuously_true() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&Filter::And(vec![]), &a));
    }

    #[test]
    fn filter_empty_or_is_vacuously_false() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&Filter::Or(vec![]), &a));
    }

    #[test]
    fn filter_unimplemented_always_false() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(!matches_filter(&Filter::GreaterOrEqual, &a));
        assert!(!matches_filter(&Filter::LessOrEqual, &a));
        assert!(!matches_filter(&Filter::ApproxMatch, &a));
    }

    #[test]
    fn filter_and_both_match() {
        let a = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["alice"]),
        ]);
        let f = Filter::And(vec![
            eq("objectClass", "posixAccount"),
            eq("uid", "alice"),
        ]);
        assert!(matches_filter(&f, &a));
    }

    #[test]
    fn filter_and_one_fails() {
        let a = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["alice"]),
        ]);
        let f = Filter::And(vec![
            eq("objectClass", "posixAccount"),
            eq("uid", "bob"),
        ]);
        assert!(!matches_filter(&f, &a));
    }

    #[test]
    fn filter_or_one_matches() {
        let a = attrs(&[("uid", &["alice"])]);
        let f = Filter::Or(vec![eq("uid", "alice"), eq("uid", "bob")]);
        assert!(matches_filter(&f, &a));
    }

    #[test]
    fn filter_or_none_match() {
        let a = attrs(&[("uid", &["alice"])]);
        let f = Filter::Or(vec![eq("uid", "bob"), eq("uid", "carol")]);
        assert!(!matches_filter(&f, &a));
    }

    #[test]
    fn filter_not() {
        let a = attrs(&[("uid", &["alice"])]);
        assert!(matches_filter(&Filter::Not(Box::new(eq("uid", "bob"))), &a));
        let not_alice = Filter::Not(Box::new(eq("uid", "alice")));
        assert!(!matches_filter(&not_alice, &a));
    }

    #[test]
    fn filter_nested_and_or() {
        // (&(objectClass=posixAccount)(|(uid=alice)(uid=bob)))
        let a = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["alice"]),
        ]);
        let f = Filter::And(vec![
            eq("objectClass", "posixAccount"),
            Filter::Or(vec![eq("uid", "alice"), eq("uid", "bob")]),
        ]);
        assert!(matches_filter(&f, &a));

        let b = attrs(&[
            ("objectClass", &["posixAccount"]),
            ("uid", &["carol"]),
        ]);
        assert!(!matches_filter(&f, &b));
    }

    // Filter: substrings

    #[test]
    fn filter_substring_initial() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        let f = Filter::Substrings {
            attr: "cn".into(),
            initial: Some("Alice".into()),
            any: vec![],
            final_: None,
        };
        assert!(matches_filter(&f, &a));

        let f2 = Filter::Substrings {
            attr: "cn".into(),
            initial: Some("Bob".into()),
            any: vec![],
            final_: None,
        };
        assert!(!matches_filter(&f2, &a));
    }

    #[test]
    fn filter_substring_final() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        let f = Filter::Substrings {
            attr: "cn".into(),
            initial: None,
            any: vec![],
            final_: Some("Smith".into()),
        };
        assert!(matches_filter(&f, &a));

        let f2 = Filter::Substrings {
            attr: "cn".into(),
            initial: None,
            any: vec![],
            final_: Some("Jones".into()),
        };
        assert!(!matches_filter(&f2, &a));
    }

    #[test]
    fn filter_substring_any() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        let f = Filter::Substrings {
            attr: "cn".into(),
            initial: None,
            any: vec!["lic".into()],
            final_: None,
        };
        assert!(matches_filter(&f, &a));
    }

    #[test]
    fn filter_substring_combined() {
        // (cn=Al*ce Sm*)
        let a = attrs(&[("cn", &["Alice Smith"])]);
        let f = Filter::Substrings {
            attr: "cn".into(),
            initial: Some("Al".into()),
            any: vec!["ce Sm".into()],
            final_: None,
        };
        assert!(matches_filter(&f, &a));
    }

    #[test]
    fn filter_substring_case_insensitive() {
        let a = attrs(&[("cn", &["Alice Smith"])]);
        let f = Filter::Substrings {
            attr: "CN".into(),
            initial: Some("alice".into()),
            any: vec![],
            final_: None,
        };
        assert!(matches_filter(&f, &a));
    }

    // Message parsing: BindRequest

    // Anonymous bind: msgId=1, version=3, name="", simple=""
    // 30 0c 02 01 01 60 07 02 01 03 04 00 80 00
    const ANON_BIND: &[u8] = &[
        0x30, 0x0c,
          0x02, 0x01, 0x01,
          0x60, 0x07,
            0x02, 0x01, 0x03,
            0x04, 0x00,
            0x80, 0x00,
    ];

    #[test]
    fn parse_anonymous_bind_request() {
        let msg = parse_message(ANON_BIND).unwrap();
        assert_eq!(msg.message_id, 1);
        let LdapOperation::BindRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.name, "");
        let BindAuth::Simple(pw) = req.auth;
        assert_eq!(pw, "");
    }

    // Authenticated bind: msgId=2, version=3,
    //   name="uid=alice,ou=people,dc=local", simple="secret"
    // Constructed by hand:
    //   name = "uid=alice,ou=people,dc=local" (28 bytes = 0x1c)
    //   password = "secret" (6 bytes)
    //   BindRequest content: 02 01 03  04 1c [name]  80 06 [pw]
    //     = 3+2+28+2+6 = 41 = 0x29
    //   msgId: 02 01 02 (3 bytes)
    //   Sequence content: 3 + 2 + 41 = 46 = 0x2e
    const AUTH_BIND: &[u8] = &[
        0x30, 0x2e,
          0x02, 0x01, 0x02,
          0x60, 0x29,
            0x02, 0x01, 0x03,
            0x04, 0x1c,
              b'u',b'i',b'd',b'=',b'a',b'l',b'i',b'c',b'e',b',',
              b'o',b'u',b'=',b'p',b'e',b'o',b'p',b'l',b'e',b',',
              b'd',b'c',b'=',b'l',b'o',b'c',b'a',b'l',
            0x80, 0x06,
              b's',b'e',b'c',b'r',b'e',b't',
    ];

    #[test]
    fn parse_authenticated_bind_request() {
        let msg = parse_message(AUTH_BIND).unwrap();
        assert_eq!(msg.message_id, 2);
        let LdapOperation::BindRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.name, "uid=alice,ou=people,dc=local");
        let BindAuth::Simple(pw) = req.auth;
        assert_eq!(pw, "secret");
    }

    // Message parsing: SearchRequest

    // Search: msgId=3, base="ou=people,dc=local" (18 bytes=0x12),
    //   scope=subtree(2), deref=0, sizeLimit=0, timeLimit=0,
    //   typesOnly=false, filter=(uid=alice), attrs=[]
    //
    // filter (uid=alice): a3 0c  04 03 "uid"  04 05 "alice"  = 14 bytes
    // SearchReq content:
    //   04 12 [base]  0a 01 02  0a 01 00  02 01 00  02 01 00
    //   01 01 00  [filter]  30 00
    //   = 20 + 3 + 3 + 3 + 3 + 3 + 14 + 2 = 51 = 0x33
    // msgId: 02 01 03 (3)
    // Sequence content: 3 + 2 + 51 = 56 = 0x38
    const SEARCH_UID_ALICE: &[u8] = &[
        0x30, 0x38,
          0x02, 0x01, 0x03,
          0x63, 0x33,
            0x04, 0x12,
              b'o',b'u',b'=',b'p',b'e',b'o',b'p',b'l',b'e',b',',
              b'd',b'c',b'=',b'l',b'o',b'c',b'a',b'l',
            0x0a, 0x01, 0x02,  // scope = wholeSubtree
            0x0a, 0x01, 0x00,  // deref = neverDerefAliases
            0x02, 0x01, 0x00,  // sizeLimit = 0
            0x02, 0x01, 0x00,  // timeLimit = 0
            0x01, 0x01, 0x00,  // typesOnly = false
            0xa3, 0x0c,        // equalityMatch
              0x04, 0x03, b'u',b'i',b'd',
              0x04, 0x05, b'a',b'l',b'i',b'c',b'e',
            0x30, 0x00,        // attributes = []
    ];

    #[test]
    fn parse_search_request_uid_equality() {
        let msg = parse_message(SEARCH_UID_ALICE).unwrap();
        assert_eq!(msg.message_id, 3);
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.base_dn, "ou=people,dc=local");
        assert_eq!(req.scope, Scope::WholeSubtree);
        assert!(req.attributes.is_empty());
        let Filter::EqualityMatch { attr, value } = req.filter
            else { panic!("wrong filter") };
        assert_eq!(attr, "uid");
        assert_eq!(value, "alice");
        // Wire-format fields size_limit/time_limit/types_only are parsed
        // and discarded; not present in SearchRequest.
    }

    // Search with AND filter: (&(objectClass=posixAccount)(uid=alice))
    // Outer AND: a0 [len] [child1] [child2]
    //   "objectClass" = 11 chars, "posixAccount" = 12 chars
    //   child1: a3  04 0b [11]  04 0c [12]
    //     content = 2+11+2+12 = 27; a3 1b [27 bytes] = 29
    //   child2: a3 0c  04 03 "uid"  04 05 "alice"  = 14 bytes
    //   AND content: 29 + 14 = 43 = 0x2b; filter: a0 2b [..] = 45 bytes
    //
    // SearchReq content:
    //   04 00 [base=""]  0a 01 02  0a 01 00  02 01 00  02 01 00
    //   01 01 00  [45-byte filter]  30 00
    //   = 2 + 3 + 3 + 3 + 3 + 3 + 45 + 2 = 64 = 0x40
    // msgId: 02 01 04 (3)
    // Seq content: 3 + 2 + 64 = 69 = 0x45
    const SEARCH_AND_FILTER: &[u8] = &[
        0x30, 0x45,
          0x02, 0x01, 0x04,
          0x63, 0x40,
            0x04, 0x00,        // base = ""
            0x0a, 0x01, 0x02,  // scope = wholeSubtree
            0x0a, 0x01, 0x00,
            0x02, 0x01, 0x00,
            0x02, 0x01, 0x00,
            0x01, 0x01, 0x00,
            0xa0, 0x2b,        // AND
              0xa3, 0x1b,      // equalityMatch objectClass=posixAccount
                0x04, 0x0b,
                  b'o',b'b',b'j',b'e',b'c',b't',b'C',b'l',b'a',b's',b's',
                0x04, 0x0c,
                  b'p',b'o',b's',b'i',b'x',b'A',b'c',b'c',b'o',b'u',b'n',b't',
              0xa3, 0x0c,      // equalityMatch uid=alice
                0x04, 0x03, b'u',b'i',b'd',
                0x04, 0x05, b'a',b'l',b'i',b'c',b'e',
            0x30, 0x00,
    ];

    #[test]
    fn parse_search_request_and_filter() {
        let msg = parse_message(SEARCH_AND_FILTER).unwrap();
        assert_eq!(msg.message_id, 4);
        let LdapOperation::SearchRequest(req) = msg.operation
            else { panic!("wrong op") };
        assert_eq!(req.base_dn, "");
        let Filter::And(children) = req.filter
            else { panic!("expected AND") };
        assert_eq!(children.len(), 2);
        let Filter::EqualityMatch { attr: a1, value: v1 } = &children[0]
            else { panic!() };
        assert_eq!(a1, "objectClass");
        assert_eq!(v1, "posixAccount");
        let Filter::EqualityMatch { attr: a2, value: v2 } = &children[1]
            else { panic!() };
        assert_eq!(a2, "uid");
        assert_eq!(v2, "alice");
    }

    // Message encoding: BindResponse

    #[test]
    fn encode_bind_response_success() {
        let msg = LdapMessage {
            message_id: 1,
            operation: LdapOperation::BindResponse(LdapResult::success()),
        };
        let bytes = encode_message(&msg);
        // Re-parse and verify it's a valid LDAP message
        let (seq, _) = ber::expect_tag(&bytes, ber::TAG_SEQUENCE).unwrap();
        let (id, rest) = ber::decode_integer(seq).unwrap();
        assert_eq!(id, 1);
        // BindResponse tag is 0x61
        let (tag, value, _) = ber::parse_tlv(rest).unwrap();
        assert_eq!(tag, 0x61);
        // Result code should be 0 (success)
        let (code, _) = ber::decode_enumerated(value).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn encode_bind_response_error() {
        let msg = LdapMessage {
            message_id: 5,
            operation: LdapOperation::BindResponse(
                LdapResult::error(INVALID_CREDENTIALS, "bad password"),
            ),
        };
        let bytes = encode_message(&msg);
        let (seq, _) = ber::expect_tag(&bytes, ber::TAG_SEQUENCE).unwrap();
        let (id, rest) = ber::decode_integer(seq).unwrap();
        assert_eq!(id, 5);
        let (_, value, _) = ber::parse_tlv(rest).unwrap();
        let (code, rest) = ber::decode_enumerated(value).unwrap();
        assert_eq!(code, INVALID_CREDENTIALS);
        let (_matched_dn, rest) = ber::decode_string(rest).unwrap();
        let (diag, _) = ber::decode_string(rest).unwrap();
        assert_eq!(diag, "bad password");
    }
}
