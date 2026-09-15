# Native TOML configuration

The installed native `tcpcc` command supports an explicit versioned TOML
configuration file for long-lived service deployments. Configuration is never
loaded implicitly: the operator must pass `--config FILE`.

```bash
sudo tcpcc --config /etc/tcpcc/tcpcc.toml
sudo tcpcc --check --config /etc/tcpcc/tcpcc.toml
```

`--check` is the only command-line service option that may be combined with
`--config`. Mixing a configuration file with direct runtime options such as
`--forward`, `--cc`, `--memory-mib`, or firewall/TUN tuning is rejected instead
of defining an override precedence hierarchy.

## Schema version 1

`version` is the configuration schema version, not the tcpcc program or Linux
version. Version 1 requires `cc` and one or more `[[forward]]` tables:

```toml
version = 1
cc = "bbr"
memory_mib = 128
firewall_backend = "nft-lib"

[[forward]]
listen = "203.0.113.10:443"
backend = "127.0.0.1:8443"

[[forward]]
listen = "203.0.113.10:8443"
backend = "127.0.0.1:9443"
```

The complete version-1 keys are:

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `version` | integer | yes | Configuration schema version; must be `1`. |
| `cc` | string | yes | Hosted public-listener TCP congestion-control algorithm. |
| `kernel` | string | no | Hosted `vmlinux` path. |
| `memory_mib` | integer | no | Hosted memory arena in MiB; default `128`, minimum `32`. |
| `tcp_wmem_max_kib` | integer | no | Explicit hosted TCP send-autotune ceiling in KiB; omit for upstream RAM-derived policy. |
| `firewall_backend` | string | no | `nft-lib`, `nft-exec`, or `iptables`; default `nft-lib`. |
| `iptables_variant` | string | no | `iptables`, `iptables-nft`, or `iptables-legacy`; valid only with the `iptables` backend. |
| `tun_name` | string | no | Explicit nonpersistent TUN name. |
| `tun_host_address` | string | no | Host-side point-to-point address. |
| `tun_guest_address` | string | no | Hosted point-to-point address. |
| `backlog` | integer | no | Listener backlog, `1..4096`; default `128`. |
| `max_connections` | integer | no | Aggregate service admission limit, `0..1048575`; `0` disables the policy limit. |
| `shutdown_grace_period` | number | no | Graceful drain timeout in seconds, `0..300`; default `5`. |
| `[[forward]]` | table array | yes | One complete public-listener/backend mapping. |

Each `[[forward]]` table contains exactly these keys:

```toml
[[forward]]
listen = "203.0.113.10:443"
backend = "127.0.0.1:8443"
```

`listen` accepts literal IPv4 `ADDRESS:PORT` or bracketed IPv6
`[ADDRESS]:PORT`. `backend` must be IPv4 loopback `127.0.0.1:PORT`. All public
listeners in one process must use one address family and distinct public ports,
matching the direct native CLI contract.

Unknown top-level keys, unknown `[[forward]]` keys, duplicate TOML keys, wrong
value types, unsupported schema versions, malformed endpoints, mixed public
address families, duplicate public ports, and non-loopback backends are fatal.
The TOML parser handles syntax; tcpcc then routes the parsed service values
through the same native validation/runtime path used by direct CLI operation.

The repository includes [`examples/tcpcc.toml`](../examples/tcpcc.toml) as a
starting point.

## Parser dependency

TOML parsing uses `toml-c` in header-only mode. The repository tracks
`chenmiaoming/toml-c` as a git submodule pinned to an exact commit; tcpcc does
not dynamically link `libtoml.so` and the installed runtime has no TOML library
package dependency.

A recursive clone fetches the dependency immediately:

```bash
git clone --recurse-submodules https://github.com/chenmiaoming/linux-tcp-cc.git
```

For an ordinary git clone, `make native-build` initializes the pinned submodule
on demand. Once the submodule is present, normal rebuilds require no network
access.

GitHub-generated source ZIP/TAR archives do not embed git submodule contents.
Building from those archives therefore requires obtaining the pinned
`chenmiaoming/toml-c` submodule separately; the published tcpcc binary packages
already contain the parser code and its MIT license and have no runtime fetch or
TOML-library dependency.

The submodule commit is part of the parent repository tree, so updates to the
fork's `main` branch do not silently change tcpcc builds. Updating the parser is
an explicit reviewed change to the gitlink commit.

## Lifecycle

Configuration is startup-only. tcpcc does not watch the file and does not
implement SIGHUP hot reload. Changing listener, TUN, firewall, congestion-control,
or resource settings requires restarting the supervisor so the existing
transactional setup/cleanup path remains authoritative.
