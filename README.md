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

Bind requests are authenticated via PAM. Anonymous binds are accepted.

## Building

```
cargo build --release
```

## Usage

```
pwldapd [OPTIONS]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-l`, `--listen ADDR` | `127.0.0.1:389` | Plain (non-TLS) address to listen on; may be repeated |
| `--tls-listen ADDR` | — | TLS address to listen on; may be repeated; requires `--tls-cert` and `--tls-key` |
| `-b`, `--base-dn DN` | derived from hostname | LDAP base DN |
| `-u`, `--uid-range N[-M]` | `1000-65535` | Restrict served accounts to this UID range; may be repeated |
| `-g`, `--gid-range N[-M]` | — | Restrict served groups to this GID range; may be repeated; primary groups of served users are always included |
| `--tls-cert FILE` | — | PEM certificate for LDAPS (requires `--tls-key`) |
| `--tls-key FILE` | — | PEM private key for LDAPS (requires `--tls-cert`) |

### Base DN

If `--base-dn` is not given, the base DN is derived from the fully-qualified
hostname. For example, on a host named `server.example.com` the base DN
becomes `dc=server,dc=example,dc=com`. If the hostname is unqualified,
`pwldapd` attempts a DNS canonical-name lookup to find the FQDN.

### IPv6

Use bracket notation for IPv6 addresses:

```
pwldapd --listen [::1]:389
pwldapd --listen [::]:389
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

Use `--tls-listen` with a PEM certificate and private key to accept TLS
connections. The standard LDAPS port is 636:

```
pwldapd --tls-listen [::]:636 \
        --tls-cert /etc/ssl/certs/ldap.pem \
        --tls-key  /etc/ssl/private/ldap.key
```

Plain and TLS listeners can run together. The `--listen` and `--tls-listen`
options may each be repeated any number of times:

```
pwldapd --listen 127.0.0.1:389 \
        --tls-listen [::]:636  \
        --tls-cert /etc/ssl/certs/ldap.pem \
        --tls-key  /etc/ssl/private/ldap.key
```

### UID ranges

Use `--uid-range` to limit which accounts are served. The option may be
repeated to allow multiple disjoint ranges:

```
# Serve only regular user accounts
pwldapd --uid-range 1000-65535

# Serve two specific service accounts as well
pwldapd --uid-range 1000-65535 --uid-range 200 --uid-range 201
```

### GID ranges

Use `--gid-range` to limit which groups are served. Without this option all
groups are served. Primary groups of served users are always visible regardless
of the GID range, so that user entries always have a resolvable `gidNumber`.

```
# Serve only groups in the regular user range
pwldapd --gid-range 1000-65535

# Serve two specific service groups as well
pwldapd --gid-range 1000-65535 --gid-range 200 --gid-range 201
```

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
- **StartTLS** — use a dedicated LDAPS port (`--tls-listen`) instead.
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
