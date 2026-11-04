# Interop testing

## Against fwknop-go (automated)

```bash
make interop
```

This builds fwknop-go's binaries from `FWKNOP_GO_DIR` (default
`../fwknop-go`) at `FWKNOP_GO_REF` (default `mlbright/main`) and runs
`crates/interop-tests`: the Rust client against the Go server, the Go client
against the Rust server (every digest × HMAC × encryption mode, plus NAT,
local NAT, client timeout, server command and replay), and both converters on
the same legacy configs.

## Against C fwknopd (by hand)

Shared test keys (already in `access.yaml` here):

```text
KEY_BASE64:      bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=
HMAC_KEY_BASE64: ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=
```

### Terminal 1: start the C fwknopd

Give C fwknopd an `access.conf` with the same keys:

```text
SOURCE            ANY
OPEN_PORTS        tcp/22
KEY_BASE64        bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=
HMAC_KEY_BASE64   ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=
HMAC_DIGEST_TYPE  sha256
```

and run it in the foreground in test mode (no firewall changes); `sudo` may
be needed to capture packets:

```bash
sudo fwknopd -c fwknopd.conf -a access.conf -f -t -v
```

### Terminal 2: send from the Rust client

```bash
cargo run -p fwknop-cli -- \
    -D 127.0.0.1 \
    -A tcp/22 \
    -a 127.0.0.1 \
    --key-base64 'bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=' \
    --key-base64-hmac 'ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=' \
    -v
```

To test the other direction, run the Rust server with this directory's
`access.yaml` and send from the C client:

```bash
cargo run -p fwknopd -- -c /dev/null -a test/interop/access.yaml -f -t -v
```

## What to look for

**Success**: the server log shows the packet from 127.0.0.1, a successful
HMAC check and decryption, and the decoded fields (username, access message,
timestamp, …).

**Failure**: look for

- HMAC verification failed: a key mismatch or wire-format problem
- decryption failed: a wrong encryption key or encryption mode
- digest verification failed: an encoding mismatch
