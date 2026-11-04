# Differences from fwknop-go

fwknop-rs is a drop-in replacement for [fwknop-go](https://github.com/mlbright/fwknop-go)
(branch `mlbright/main`): the same binaries, flags, YAML files, environment
variables and wire protocol. This page lists every place where it behaves
differently on purpose. Anything not listed here should match Go; a
difference that is not listed is a bug.

## Bugs fixed

- **`fwknopd -R/--restart` restarts the server.** Go handled SIGHUP like
  SIGTERM, so "restart" stopped the server. Now SIGHUP re-reads `server.yaml`,
  `access.yaml` and the action template. If they are invalid the error is
  logged and the server keeps running on the old configuration; otherwise
  every open rule is closed, the `shutdown` action runs, and the server starts
  again with the new configuration. The replay cache is kept, so packets
  received before the restart cannot be replayed after it.
- **`fwknopd` without `--foreground` runs in the background.** Go never
  detached; the flag only switched logging to file and syslog. Startup errors
  (bad configuration, port in use, failing `validate` or `init` action) are
  still reported on the terminal with a non-zero exit code, because they
  happen before the server detaches. It refuses to start when the PID file
  names a running fwknopd.
- **Replay protection stays on when `max_spa_packet_age` is 0.** Go sized
  the replay cache's lifetime from the max packet age, so with the age check
  off every replayed packet was accepted. fwknop-rs then keeps replay
  digests for the life of the process.
- **The PID file is removed on shutdown.** Go deferred the removal but left
  through `os.Exit`, which skips deferred calls.
- **PID files are parsed correctly.** Go dropped the last byte of the file
  unconditionally: an empty file crashed `-S`, `-K` and `-R`, and a PID file
  without a trailing newline lost a digit.
- **No races between rule timers, refreshes and shutdown.** All rules are
  owned by one event loop, so a timer that fires during a refresh no longer
  drops the refreshed rule, and a rule opened while the server shuts down is
  always closed.
- **A second knock for an open rule only extends it.** If the server already
  tracks the rule for that allow IP and access spec it resets the timer and
  runs neither `check` nor `open`. Go ran `open` again when no `check` action
  was configured, adding a duplicate firewall rule that was never closed. As
  in Go, the most recent knock's timeout wins.
- **`fwknop -C <cmd>` does not ask for an allow IP**, which a command message
  never carries.
- **`fwknop --stanza-list` prints rc stanzas in file order** instead of random
  order.
- **Syslog messages carry their real severity** (`LOG_WARNING`, `LOG_ERR`).
  Go sent everything at `LOG_INFO` with a text prefix.
- **`cmd_exec_user` works on macOS.** Go ran `su -c <cmd> <user>`, which
  macOS `su` rejects; fwknop-rs runs `su <user> -c <cmd>`, which works on
  Linux and macOS.
- **SHA3 message digests are reported as SHA3.** Go's decoder accepted a
  SHA3-256 or SHA3-512 digest but reported it as SHA256 or SHA512 (in
  `fwknopd`'s "Digest Type" log line, for example).
- **Unknown placeholders are caught at startup.** Go accepted `{{.Typo}}` in
  an action and failed only when a packet arrived.

## Removed

- The client flags `--nat-port` and `--save-rc-stanza` and the server key
  `run_dir`, which Go accepted but never used. `run_dir` in an existing
  `server.yaml` is ignored like any other unknown key; the two flags are now
  rejected as unknown. `fwknop-convert` no longer emits `run_dir` or
  `nat_port`.
- Windows support. Go's `fwknopd` never built on Windows; fwknop-rs supports
  Linux and macOS only.
- The `lib`, `retest` and `tidy` Makefile targets, which have no Cargo
  equivalent. `vet` is now `lint`.

## Changed on purpose

- **`-V` says "(Rust)"** instead of "(Go)".
- **`--help` output uses clap's layout.** The flags themselves are unchanged.
- **Log messages say "access stanza #N"** where Go said "stanza #N".
- **Ports are normalised.** The client sends `tcp/022` as `tcp/22`. The Go
  client accepted the leading zero but the Go server rejected it.
- **Action placeholders are limited to `{{.Name}}`.** Go actions accepted the
  whole `text/template` language; see
  [ADR 0001](adr/0001-go-template-placeholder-syntax.md).
- **The decoder rejects a client-timeout message type without a timeout
  field.** Go accepted it and treated the timeout as 0.
- **Version numbers come from each crate's `Cargo.toml`.** There is no
  build-time override like Go's `-ldflags "-X main.version=…"`.
- **SPA message fields must be UTF-8.** A decoded username, access message,
  NAT access, server auth or server command that is not valid UTF-8 is
  rejected. Go accepted arbitrary bytes.
- **Usernames with unassigned Unicode code points are accepted.** Go's
  `unicode.IsPrint` rejects them; Rust's standard library has no table for
  them. Control, whitespace, format and private-use characters are still
  rejected, as in Go.

## Library API

The `fkospa` and `fwknop` crates keep the behaviour of the Go packages but
not their shape: an `SpaMessage` with a typed `Request` replaces the flat
`Message` struct and its functional options, a `KeySet` carries the keys and
modes, and the encryption modes Go defined but never implemented (ECB, CFB,
PCBC, OFB, CTR) are gone, along with the `Encrypter`, `Decrypter` and
`KeyDeriver` interfaces nothing could plug into. See the
[fkospa guide](../doc/fkospa-guide.md).
