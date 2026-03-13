# pwldapd

An LDAP server backed by the local POSIX user and group database. It lets
LDAP-aware applications look up system accounts and authenticate users via
PAM, without maintaining a separate directory.

## What it serves

The directory tree mirrors `/etc/passwd` and `/etc/group`:

```
dc=host,dc=example,dc=com
├── ou=people
│   ├── uid=alice,...
│   └── uid=bob,...
└── ou=groups
    ├── cn=staff,...
    └── cn=wheel,...
```

Each user entry carries the standard `posixAccount` and `inetOrgPerson`
attributes (`uid`, `cn`, `sn`, `uidNumber`, `gidNumber`, `homeDirectory`,
`loginShell`, `gecos`). The GECOS field is parsed using the traditional
BSD format to populate `givenName`, `roomNumber`, `telephoneNumber`, and
`homePhone` when those fields are non-empty. Each group entry carries
`posixGroup` attributes (`cn`, `gidNumber`, `memberUid`).

Additional attributes can be added to user entries via the configuration
file (see [User attributes](#user-attributes) below).

Bind requests are authenticated via PAM. Anonymous binds are accepted.

## Building

```
cargo build --release
```

## Building a Debian package

Install `cargo-deb` once, then build:

```sh
cargo install cargo-deb
cargo deb
```

The resulting `.deb` is written to `target/debian/`. Install it with:

```sh
sudo dpkg -i target/debian/pwldapd_0.1.0_amd64.deb
```

The package installs:
- `/usr/sbin/pwldapd` — the daemon binary, with `CAP_NET_BIND_SERVICE` set
- `/usr/share/man/man8/pwldapd.8` — man page
- `/etc/pam.d/pwldapd` — default PAM configuration (treated as a conffile)
- `/lib/systemd/system/pwldapd.service` — systemd unit

The service is enabled automatically on install. To start it immediately:

```sh
sudo systemctl start pwldapd
```

## Usage

```
pwldapd [-c FILE]
```

Without a config file, `pwldapd` starts with built-in defaults: listening on
`127.0.0.1:389`, base DN derived from the system hostname, and UID range
`1000-65535`. All other options require a configuration file.

### Configuration file

Load a TOML configuration file with `--config`. An example covering every
option:

```toml
listen     = ["127.0.0.1:389"]
tls_listen = ["[::]:636"]
base_dn    = "dc=example,dc=com"
uid_ranges = ["1000-65535"]
gid_ranges = ["1000-65535"]
tls_cert   = "/etc/ssl/certs/ldap.pem"
tls_key    = "/etc/ssl/private/ldap.key"

[user_attributes]
mail       = "{uid}@example.com"
department = "Engineering"

[user_overrides.alice]
mail       = "alice@external.com"
department = "Platform Engineering"
```

Unknown keys in the file are treated as errors so that typos are caught
at startup rather than silently ignored.

### User attributes

The `[user_attributes]` section adds or replaces attributes on every user
entry. Values are either fixed strings or templates containing
`{placeholder}` sequences:

| Placeholder | Value |
|-------------|-------|
| `{uid}` | Username |
| `{cn}` | Common name (from GECOS) |
| `{sn}` | Surname (last word of cn) |
| `{uidNumber}` | Numeric UID |
| `{gidNumber}` | Numeric GID |
| `{homeDirectory}` | Home directory path |
| `{shell}` | Login shell |
| `{gecos}` | Raw GECOS field |

An unknown placeholder such as `{email}` is a fatal error at startup.

Values in `[user_attributes]` may replace built-in attributes such as
`loginShell` or `cn`. The core identity attributes `objectClass`, `uid`,
`uidNumber`, and `gidNumber` are protected and cannot be replaced; attempts
produce a warning and are ignored.

The `[user_overrides.<username>]` section sets fixed attribute values for
a specific user. These take precedence over the general `[user_attributes]`
rules. Templates are not supported in per-user overrides.

### Base DN

If `base_dn` is not set in the config file, the base DN is derived from the
fully-qualified hostname. For example, on a host named `server.example.com`
the base DN becomes `dc=server,dc=example,dc=com`. If the hostname is
unqualified, `pwldapd` attempts a DNS canonical-name lookup to find the FQDN.

### IPv6

Use bracket notation for IPv6 addresses in `listen` and `tls_listen`:

```toml
listen     = ["[::1]:389"]
tls_listen = ["[::]:636"]
```

### Listening on port 389

Port 389 requires elevated privileges. The recommended approach is to grant
the binary the `CAP_NET_BIND_SERVICE` capability rather than running as root:

```
sudo setcap cap_net_bind_service=ep ./target/release/pwldapd
```

Alternatively, use a high port and redirect with a firewall rule, or run
under a service manager that provides socket activation.

### TLS (LDAPS)

Set `tls_listen`, `tls_cert`, and `tls_key` in the config file to accept TLS
connections. Plain and TLS listeners can run together:

```toml
listen     = ["127.0.0.1:389"]
tls_listen = ["[::]:636"]
tls_cert   = "/etc/ssl/certs/ldap.pem"
tls_key    = "/etc/ssl/private/ldap.key"
```

### UID and GID ranges

Use `uid_ranges` and `gid_ranges` to limit which accounts and groups are
served. Multiple disjoint ranges are supported:

```toml
uid_ranges = ["1000-65535", "200", "201"]
gid_ranges = ["1000-65535"]
```

Without `gid_ranges`, all groups are served. Primary groups of served users
are always visible regardless of the GID range.

### Logging

Log verbosity is controlled with the `RUST_LOG` environment variable:

```
RUST_LOG=pwldapd=debug pwldapd
```

## PAM configuration

`pwldapd` authenticates bind requests through the PAM service named
`pwldapd`. Create `/etc/pam.d/pwldapd` before starting the daemon.
A minimal configuration that delegates to the standard system auth stack:

```
auth     required   pam_unix.so
account  required   pam_unix.so
```

Or, on systems that use the include-based layout:

```
@include common-auth
@include common-account
```

Using a dedicated service name lets you apply LDAP-specific policies
independently of console login — for example, adding a failure delay or
restricting which accounts may bind via LDAP.

## Limitations

`pwldapd` is intentionally a read-only LDAP front-end. The following
features are not supported:

- **Write operations** — Add, Delete, Modify, and ModifyDN requests are
  not handled.
- **SASL authentication** — only simple binds (anonymous or
  username/password) are supported.
- **StartTLS** — use a dedicated LDAPS port (`tls_listen`) instead.
- **Referrals and server-side sorting.**
- **Size and time limits** — client-requested values are accepted on the
  wire but not enforced.
- **Persistent searches and change notifications.**

## Example: NSS/LDAP client configuration

Point your LDAP client at the daemon. With `nss-pam-ldapd` or `sssd`, use:

```
uri     ldap://127.0.0.1/
base    dc=host,dc=example,dc=com
```

Replace the base DN with whatever `pwldapd` logs at startup.
