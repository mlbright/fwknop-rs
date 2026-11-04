# fwknop-rs

[![CI](https://github.com/mlbright/fwknop-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mlbright/fwknop-rs/actions/workflows/ci.yml)

A Rust implementation of [fwknop](https://www.cipherdyne.org/fwknop/)
(FireWall KNock OPerator): Single Packet Authorization (SPA) for strong
service concealment. It is a translation of
[fwknop-go](https://github.com/mlbright/fwknop-go) and a drop-in replacement
for it: the same binaries, flags, YAML files, environment variables and wire
protocol (SPA protocol 3.0.0, compatible with the C fwknop as well).

The few places where it behaves differently from fwknop-go, mostly bug
fixes, are listed in [docs/deviations-from-go.md](docs/deviations-from-go.md).
The project's vocabulary is in [GLOSSARY.md](GLOSSARY.md) and its key
decisions are in [docs/adr/](docs/adr/).

## Overview

| Crate | What it is |
|-------|------------|
| `fkospa` | Library: the SPA protocol (encode, encrypt, HMAC, decrypt, decode) |
| `fwknop` | Library: send an SPA knock in one call (`Knock::new(..).send()`) |
| `fwknop-cli` | The `fwknop` client, which sends SPA requests |
| `fwknopd` | The `fwknopd` server, which receives SPA packets and runs actions to open firewall access |
| `fwknop-convert` | Converts legacy C fwknop config files to YAML |

Linux and macOS are supported. CI runs the tests, and the interop tests
against fwknop-go, on Linux.

## Installation

From a checkout:

```bash
make install     # cargo install fwknop, fwknopd and fwknop-convert into ~/.cargo/bin
```

Or straight from git:

```bash
cargo install --git https://github.com/mlbright/fwknop-rs fwknop-cli fwknopd fwknop-convert
```

## Project layout

```text
fwknop-rs/
├── crates/
│   ├── fkospa/           # SPA protocol library (+ examples/, tests/testdata/ golden vectors)
│   ├── fwknop/           # one-call knock library
│   ├── fwknop-cli/       # the fwknop client
│   ├── fwknopd/          # the fwknopd server
│   ├── fwknop-convert/   # legacy config converter
│   ├── cli-common/       # config layering shared by the binaries (internal)
│   ├── buildinfo/        # version and git metadata (internal)
│   └── interop-tests/    # Go <-> Rust tests, run with `make interop`
├── conf_files/           # reference server, access and action-template configs
├── examples/configs/     # sample client and server configs
├── systemd/              # systemd unit
├── test/interop/         # notes and keys for testing against C fwknopd
├── doc/fkospa-guide.md   # fkospa developer guide
└── docs/                 # ADRs and the list of differences from fwknop-go
```

## Building

The repository pins Rust 1.99.1 in `rust-toolchain.toml`; rustup installs it
on first use.

```bash
make all        # Build fwknop, fwknopd and fwknop-convert into bin/
make client     # bin/fwknop
make server     # bin/fwknopd
make convert    # bin/fwknop-convert
```

Other targets:

```bash
make test       # Run all tests
make interop    # Build fwknop-go and run the Go <-> Rust interop tests
make lint       # cargo clippy with warnings as errors
make fmt        # cargo fmt
make install    # cargo install the three binaries
make help       # List all targets
```

`make interop` builds fwknop-go from `FWKNOP_GO_DIR` (default
`../fwknop-go`) at `FWKNOP_GO_REF` (default `mlbright/main`), using
`git archive` so the checkout is not touched, and needs Go installed.

To install `fwknopd` as a systemd service (Linux), see
[Running fwknopd under systemd](#running-fwknopd-under-systemd):

```bash
sudo make install-systemd     # Install fwknopd binary, systemd unit, and sample configs
sudo make uninstall-systemd   # Remove the unit and binary
```

### Versioning

Each binary is versioned by its crate's `Cargo.toml`. A build from a git
checkout also records the commit, its time and whether the tree was dirty:

```text
fwknop (Rust) version 0.1.0 (commit: fa2a972fabb4, built: 2026-04-07T03:11:46Z) (SPA protocol 3.0.0)
```

---

## Quick start

### Generate keys

```bash
fwknop --key-gen
```

```text
KEY_BASE64: <base64-encryption-key>
HMAC_KEY_BASE64: <base64-hmac-key>
```

### Send an SPA request

```bash
fwknop -D server.example.com -A tcp/22 -R \
    --key-base64 '<key>' \
    --key-base64-hmac '<hmac-key>'
```

### Start the server

```bash
fwknopd -c /etc/fwknop/server.yaml -a /etc/fwknop/access.yaml
```

Or in the foreground with verbose output, without touching the firewall:

```bash
fwknopd -c server.yaml -a access.yaml -f -t -v
```

---

## Client (`fwknop`)

The client builds an SPA packet and sends it over UDP. It supports all seven
message types, HMAC authentication and seven digest algorithms.

### Usage

```text
fwknop [options]
```

### Key options

| Flag | Description |
|------|-------------|
| `-D, --destination` | Host name or IP of the fwknop server (required) |
| `-A, --access` | Access spec to open, e.g. `tcp/22` (required unless `-C`) |
| `-a, --allow-ip` | Allow IP: the address to open access for |
| `-R, --resolve-ip` | Use your external IP (looked up over HTTPS) as the allow IP |
| `-s, --source-ip` | Send `0.0.0.0`: open access for whatever address the packet comes from |
| `--key-base64` | Base64-encoded encryption key |
| `--key` | Encryption key (passphrase) |
| `--key-base64-hmac` | Base64-encoded HMAC key |
| `--key-hmac` | HMAC key |
| `--use-hmac=false` | Send without an HMAC |
| `-n, --named-config` | Use a named rc stanza from `~/.fwknoprc` |
| `-N, --nat-access` | NAT access (`IP,port`) |
| `-C, --server-cmd` | Server command to run instead of an access request |
| `-f, --fw-timeout` | Client timeout: how long the rule should stay open, in seconds |
| `-m, --digest-type` | Message digest: `md5`, `sha1`, `sha256` (default), `sha384`, `sha512`, `sha3-256`, `sha3-512` |
| `-T, --test` | Build the packet and print it, but don't send it |
| `-k, --key-gen` | Generate random encryption and HMAC keys |
| `--stanza-list` | List the rc stanzas in the rc file |
| `-v, --verbose` | Verbose output (repeat for more) |

Run `fwknop --help` for the full list. Bool flags take an optional value
(`--use-hmac=false`); a repeated flag keeps its last value.

### Configuration

The client merges configuration from these sources, highest priority
first:

1. **Flags**: `--destination`, `--access`, etc.
2. **Environment variables**: prefixed with `FWKNOP_` and named after the
   config keys (e.g. `FWKNOP_DESTINATION`, `FWKNOP_HMAC_KEY_BASE64`)
3. **The rc stanza named with `-n`** in `~/.fwknoprc` (or `--rc-file`)
4. **The `default` rc stanza**
5. **Flag defaults**

#### rc file format (YAML)

```yaml
default:
  destination: 192.168.1.100
  access: tcp/22
  key_base64: <base64-key>
  hmac_key_base64: <base64-hmac-key>

production:
  destination: prod.example.com
  access: tcp/443
```

Select a named rc stanza with `-n`:

```bash
fwknop -n production -R
```

An access message carries one access spec, so request one port per knock.

#### Migrating from a legacy `.fwknoprc`

Convert a C fwknop rc file (INI-style `[stanza]` format) with
`fwknop-convert`:

```bash
fwknop-convert --type client --input ~/.fwknoprc > ~/.fwknoprc.yaml
```

---

## Server (`fwknopd`)

The server listens for SPA packets on a UDP port, tries each access stanza
whose source matches the packet source, and runs actions to open access for
a request that decrypts, is fresh and has not been seen before.

### Usage

```text
fwknopd [options]
```

### Key options

| Flag | Description |
|------|-------------|
| `-c, --config-file` | Server config YAML (default: `/etc/fwknop/server.yaml`) |
| `-a, --access-file` | Access stanzas YAML (default: `/etc/fwknop/access.yaml`) |
| `-f, --foreground` | Run in the foreground and log to stderr (otherwise it detaches and logs to the log file and syslog) |
| `-t, --test` | Test mode: decrypt and log packets, run no actions |
| `-D, --dump-config` | Print the resolved config and exit |
| `-K, --kill` | Stop a running fwknopd (SIGTERM) |
| `-R, --restart` | Restart a running fwknopd with fresh config (SIGHUP) |
| `-S, --status` | Check whether fwknopd is running |
| `-p, --pid-file` | PID file path |
| `-v, --verbose` | Verbose output |

Without `-f`, every startup step that can fail (loading the configs, binding
the port, the `validate` and `init` actions) happens before fwknopd detaches,
so errors reach the terminal. It refuses to start when its PID file names a
running fwknopd.

On SIGHUP (`fwknopd -R`) it re-reads `server.yaml`, `access.yaml` and the
action template. If they are invalid it logs why and keeps running on the old
configuration. Otherwise it closes every open rule, runs `shutdown`, and
starts again with `validate` and `init` from the new configuration. The
replay cache is kept.

### Server configuration (`server.yaml`)

```yaml
udp_port: 62201
bind_address: "0.0.0.0"   # 0.0.0.0 or :: listens on IPv4 and IPv6

log_file: /var/log/fwknop/fwknopd.log
syslog_identity: fwknopd
syslog_facility: daemon
verbose: false

pid_file: /var/run/fwknop/fwknopd.pid

max_spa_packet_age: 120   # seconds
```

Any key can also be set with an environment variable prefixed with
`FWKNOPD_` (e.g. `FWKNOPD_UDP_PORT=62201`).

### Actions

Actions are the shell commands fwknopd runs at each lifecycle step. All six
are optional:

```yaml
actions:
  validate: "which iptables"
  init: "iptables -N FWKNOP_INPUT 2>/dev/null; iptables -C INPUT -j FWKNOP_INPUT 2>/dev/null || iptables -I INPUT -j FWKNOP_INPUT"
  check: "iptables -C FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT 2>/dev/null"
  open: "iptables -A FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT"
  close: "iptables -D FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT"
  shutdown: "iptables -F FWKNOP_INPUT; iptables -D INPUT -j FWKNOP_INPUT; iptables -X FWKNOP_INPUT"
```

Or use an action template for your firewall, from `action_dir` (default
`/etc/fwknop/actions`); inline actions override the template's one at a
time:

```yaml
action_template: nftables.yaml
```

Action templates are provided for iptables, nftables, firewalld, pf, ipfw
and ipf in `conf_files/actions/`.

| Step | When | On failure |
|------|------|------------|
| `validate` | Startup, and before a restart | Fatal at startup; a restart keeps the old configuration |
| `init` | Startup, after validate | Fatal |
| `check` | Before opening a rule fwknopd is not already tracking | Exit 0 = the rule exists (fwknopd takes it over), non-zero = run `open` |
| `open` | On a valid access request | Logged; the rule is not tracked |
| `close` | When a rule's timeout runs out | Logged; the rule is dropped |
| `shutdown` | On SIGTERM/SIGINT, and on restart | Best effort, logged |

A second knock for a rule that is already open only resets its timeout, to
the new knock's.

#### Placeholders

`check`, `open` and `close` may contain these placeholders. Anything else in
`{{ }}` stops the server at startup (see
[ADR 0001](docs/adr/0001-go-template-placeholder-syntax.md)).

| Placeholder | Value | Example |
|-------------|-------|---------|
| `{{.SourceIP}}` | The allow IP from the access message, or the packet source when the client sent `0.0.0.0`/`::`. It equals the packet source only if the access stanza sets `require_source_address: true` | `192.168.1.50` |
| `{{.Proto}}` | Protocol from the access spec | `tcp` |
| `{{.Port}}` | Port from the access spec | `22` |
| `{{.Username}}` | Username from the SPA message (inserted shell-quoted) | `'alice'` |
| `{{.Timestamp}}` | The SPA message's Unix timestamp | `1775331907` |
| `{{.Timeout}}` | The rule's timeout in seconds | `30` |
| `{{.AccessMsg}}` | The access message (inserted shell-quoted) | `'192.168.1.50,tcp/22'` |
| `{{.NATAccess}}` | The NAT access string (inserted shell-quoted) | `'10.0.0.100,22'` |

Actions run through `/bin/sh -c`. `SourceIP`, `Proto` and `Port` always hold
a valid IP address, `tcp`/`udp`/`icmp` and a port number. `Username`,
`AccessMsg` and `NATAccess` are free text chosen by the client, so they are
inserted already single-quoted as one shell word; do not wrap them in quotes
yourself.

### Access stanzas (`access.yaml`)

Each access stanza says which packet sources it applies to, the keys a
packet must decrypt and authenticate with, and what it may open:

```yaml
- source: "192.168.1.0/24"
  open_ports:
    - tcp/22
  key_base64: "<base64-encryption-key>"
  hmac_key_base64: "<base64-hmac-key>"
  hmac_digest_type: sha256
  access_timeout: 30
  require_source_address: true

- source: "ANY"
  open_ports:
    - tcp/22
    - tcp/443
  key_base64: "<base64-encryption-key>"
  hmac_key_base64: "<base64-hmac-key>"
```

| Field | Description |
|-------|-------------|
| `source` | `ANY`, or IPs and CIDRs separated by commas, that the packet source must be in (required) |
| `open_ports` | Access specs that may be opened, e.g. `tcp/22` (empty: any) |
| `key_base64` / `key` | Encryption key (base64 or plaintext) |
| `hmac_key_base64` / `hmac_key` | HMAC key (base64 or plaintext); without one, packets without an HMAC are accepted |
| `hmac_digest_type` | HMAC algorithm (default: `sha256`) |
| `encryption_mode` | `cbc` (default) or `legacy` |
| `access_timeout` | How long a rule stays open when the client asks for no time (default: 30) |
| `max_access_timeout` | The longest client timeout honored (default: 300) |
| `require_username` | Only accept SPA messages with this username |
| `require_source_address` | The allow IP must equal the packet source |
| `enable_cmd_exec` | Allow server commands |
| `cmd_exec_user` | User to run server commands as |

### Running fwknopd under systemd

A systemd unit is provided in [`systemd/fwknopd.service`](systemd/fwknopd.service).

#### Install

From the repository root:

```bash
sudo make install-systemd
```

This target:

- builds `bin/fwknopd` and installs it to `/usr/local/bin/fwknopd`
- installs the unit to `/etc/systemd/system/fwknopd.service`
- creates `/etc/fwknop/` and copies the reference configs as
  `server.yaml.sample`, `access.yaml.sample` and the `actions/` templates
  (existing configs are **not** overwritten)

Override the install locations if needed:

```bash
sudo make install-systemd PREFIX=/usr SYSCONFDIR=/etc/fwknop UNITDIR=/lib/systemd/system
```

> If you change `PREFIX`, edit the `ExecStart=` path in
> `/etc/systemd/system/fwknopd.service` to match (it defaults to
> `/usr/local/bin/fwknopd`).

#### Configure

1. Create the real config files from the installed samples and edit them:

   ```bash
   sudo cp /etc/fwknop/server.yaml.sample /etc/fwknop/server.yaml
   sudo cp /etc/fwknop/access.yaml.sample /etc/fwknop/access.yaml
   ```

2. Generate a key pair and put it in an access stanza in `access.yaml` (the
   sample's placeholder keys are rejected, so fwknopd won't start until you
   do):

   ```bash
   fwknop --key-gen
   ```

   ```yaml
   - source: "ANY"
     open_ports:
       - tcp/22
     key_base64: "<KEY_BASE64>"
     hmac_key_base64: "<HMAC_KEY_BASE64>"
     hmac_digest_type: sha256
     access_timeout: 30
   ```

   Keep `access.yaml` readable only by root (`chmod 600`) since it holds keys.

3. Set the firewall `actions` (or `action_template`) in `server.yaml` for
   your platform. See [Actions](#actions) and the templates in
   `/etc/fwknop/actions/`.

4. Check the config before enabling the service:

   ```bash
   sudo fwknopd --dump-config
   ```

#### Enable and manage

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fwknopd     # start now and on boot

sudo systemctl status fwknopd           # check status
sudo systemctl restart fwknopd          # restart after editing configs
sudo journalctl -u fwknopd -f           # follow logs
```

`fwknopd` runs in the foreground under systemd (`Type=simple`), so systemd
supervises it directly and restarts it on failure. The unit grants
`CAP_NET_ADMIN`/`CAP_NET_RAW` for firewall management and applies a set of
hardening directives; if your actions fail to apply rules, relax the
hardening options near the bottom of the unit file.

#### Uninstall

```bash
sudo make uninstall-systemd
```

This stops and removes the service and the `/usr/local/bin/fwknopd` binary;
your configuration under `/etc/fwknop/` is left in place.

---

## Library (`fkospa`)

```rust
use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet, Request, SpaMessage};

let keys = KeySet::new(
    EncryptionKey::new("enc_key"),
    EncryptionMode::Cbc,
    Some(HmacKey::new("hmac_key", HmacType::Sha256)),
);

// Client side: build and encrypt.
let msg = SpaMessage::new(Request::access("192.168.1.1,tcp/22".parse()?))?;
let spa_data = msg.encrypt(&keys)?; // the UDP payload

// Server side: verify, decrypt and decode.
let received = SpaMessage::decrypt(&spa_data, &keys)?;
println!("User: {}, Access: {}", received.username, received.request.message_text());
# Ok::<(), fkospa::Error>(())
```

| Category | Algorithms |
|----------|-----------|
| Encryption | AES-256-CBC (default), CBC with legacy IV key padding |
| Message digest | MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-512 |
| HMAC | MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-512 |

See the [fkospa developer guide](doc/fkospa-guide.md) and the examples
(`cargo run -p fkospa --example basic_spa`, `custom_digest`, `keygen`,
`nat_access`).

## Knock library (`fwknop`)

For programs that want to open a firewall hole in process instead of
running the `fwknop` client:

```rust,no_run
use fkospa::{EncryptionKey, EncryptionMode, HmacKey, HmacType, KeySet};
use fwknop::Knock;

let keys = KeySet::new(
    EncryptionKey::from_base64("bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=")?,
    EncryptionMode::Cbc,
    Some(HmacKey::from_base64("ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=", HmacType::Sha256)?),
);
let mut knock = Knock::new("server.example.com", "203.0.113.7,tcp/22".parse()?, keys);
knock.port = 62201;
knock.send()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Defaults match the client (port 62201, SHA-256 digest, the current user, no
client timeout). `Knock::spa_data()` returns the encrypted SPA data without
sending it. `send()` blocks only for the host-name lookup.

---

## Conversion tool (`fwknop-convert`)

Converts legacy C fwknop configuration files to YAML:

```bash
fwknop-convert --type client --input ~/.fwknoprc > ~/.fwknoprc.yaml
fwknop-convert --type server --input /etc/fwknop/fwknopd.conf > server.yaml
fwknop-convert --type access --input /etc/fwknop/access.conf > access.yaml
```

Keys with no equivalent (GPG, pcap, iptables-specific settings, …) produce
warnings on stderr, with suggestions where there is one. A legacy firewall
configuration is detected and turned into the matching `action_template`.

---

## Compatibility

fwknop-rs is checked against the other implementations:

- **C fwknop**: encoding is byte-identical to libfko's for the golden
  vectors in `crates/fkospa/tests/testdata/`, and SPA data encrypted by
  libfko decrypts. Key derivation and ciphertext match OpenSSL.
- **fwknop-go**: `make interop` sends every digest × HMAC × encryption-mode
  combination, plus NAT, local NAT, client timeout, server command and
  replay cases, from the Rust client to the Go server and from the Go client
  to the Rust server, and checks that both converters produce the same
  configuration.

## License

GNU General Public License v2.0; see [LICENSE](LICENSE). fwknop-rs is a
translation of fwknop-go, which follows C fwknop; both are licensed under
the GPL v2.
