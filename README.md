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

Bind requests are authenticated via PAM. Anonymous binds are accepted by
default; use `require_bind` to restrict searches to specific accounts.

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

If `-c` is not given, `pwldapd` looks for `/etc/pwldapd.toml` and loads it
if present. Without any config file it starts with built-in defaults:
listening on `127.0.0.1:389`, base DN derived from the system hostname, and
all UIDs and GIDs served.

### Configuration file

Load a TOML configuration file with `--config` (or place it at
`/etc/pwldapd.toml` for automatic loading). An example covering every option:

```toml
include      = ["/etc/pwldapd.d/*.conf"]
listen       = ["127.0.0.1:389"]
tls_listen   = ["[::]:636"]
unix_listen  = ["/run/pwldapd/ldap.sock"]
base_dn      = "dc=example,dc=com"
uid_ranges   = ["1000-65535"]
gid_ranges   = ["1000-65535"]
tls_cert     = "/etc/ssl/certs/ldap.pem"
tls_key      = "/etc/ssl/private/ldap.key"
log_level    = "info"
require_bind = ["svcaccount"]

[user_attributes]
mail       = "{uid}@example.com"
department = "Engineering"

[user_overrides.alice]
mail       = "alice@external.com"
department = "Platform Engineering"
```

The `include` field takes a list of glob patterns. Each matching file is
loaded and merged before the values in the main file; the main file always
takes precedence. Included files may not themselves contain `include`
directives.

A port may be omitted from `listen` and `tls_listen` addresses; `:389`
and `:636` are appended automatically. To suppress the default TCP listener
(`127.0.0.1:389`), set `listen = []` explicitly.

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

Port 389 requires elevated privileges. When installed from the Debian
package, the systemd unit runs `pwldapd` as the unprivileged `pwldapd`
system user and grants `CAP_NET_BIND_SERVICE` via `AmbientCapabilities`,
so no additional configuration is needed.

When running outside of the package, grant the capability directly:

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

### Unix domain sockets

Set `unix_listen` to a list of socket paths to accept connections over a
Unix domain socket. This is useful for local clients that do not need
network access:

```toml
unix_listen = ["/run/pwldapd/ldap.sock"]
```

Multiple paths are supported. Plain TCP, TLS, and Unix listeners can all
run simultaneously.

If a socket file already exists at the path when the daemon starts (e.g.
from a previous run), it is removed and recreated automatically.

Clients connect using the `ldapi://` URI scheme. With `ldapsearch`:

```
ldapsearch -H ldapi:///run/pwldapd/ldap.sock -x -b dc=example,dc=com
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

### Requiring a bind before searches

By default any client — including unauthenticated anonymous clients — may
perform searches. Set `require_bind` to a list of account names to restrict
this: a client must successfully bind as one of those accounts before any
search request is permitted.

```toml
require_bind = ["svcaccount"]
```

This is intended for service accounts that need to authenticate themselves
to the server before retrieving directory data. When `require_bind` is set:

- An anonymous bind succeeds but subsequent searches return
  `INSUFFICIENT_ACCESS_RIGHTS` (LDAP result code 50).
- A bind as an account not in the list fails with `INVALID_CREDENTIALS`
  (the account is rejected by PAM), so searches remain blocked.
- A bind as a listed account succeeds; searches are then permitted for
  the remainder of that connection.
- Re-binding anonymously or failing a bind clears the authenticated
  identity; searches are blocked again until a successful bind.

When `require_bind` is empty (the default) all clients may search without
binding.

### Logging

Log verbosity can be set in the config file:

```toml
log_level = "debug"
```

Or with the `RUST_LOG` environment variable (takes precedence over the config file):

```
RUST_LOG=pwldapd=debug pwldapd
```

Both accept full tracing filter syntax, e.g. `"pwldapd=debug"` or `"debug"`. The default is `pwldapd=info`.

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

Or, if you configured a Unix domain socket:

```
uri     ldapi:///run/pwldapd/ldap.sock
base    dc=host,dc=example,dc=com
```

Replace the base DN with whatever `pwldapd` logs at startup.
