#!/usr/bin/env bash
# Tests the nftables and iptables action templates against the real kernel
# firewall.
#
# Everything runs inside a throwaway network namespace, which has its own
# empty ruleset, so the host's firewall is never read or changed. For each
# template it sets up a default-drop firewall, starts fwknopd in the
# foreground, and checks that a knock opens a TCP port, that the rule closes
# when its timeout runs out, that a second knock does not add a duplicate
# rule, and that shutdown removes everything fwknopd added.
#
# Needs Linux, root, ip, nft, iptables and python3:
#
#   sudo test/firewall/run.sh target/debug
set -euo pipefail

BIN_DIR=$(cd "${1:?usage: run.sh <directory with fwknop and fwknopd>}" && pwd)
REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d /tmp/fwknop-firewall-test.XXXXXX)
NS=fwknop-test-$$
SPA_PORT=62201
SVC_PORT=8022
ACCESS_TIMEOUT=3
KEY=firewall-test-key
HMAC_KEY=firewall-test-hmac
PIDS=()

# Stops every process left in the namespace, then deletes it.
delete_namespace() {
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    ip netns del "$NS" 2>/dev/null || true
}

cleanup() {
    delete_namespace
    case $WORK in /tmp/fwknop-firewall-test.*) rm -rf "$WORK" ;; esac
}
trap cleanup EXIT

# Background processes are started with "ip netns exec" directly rather than
# through in_ns, so that $! is the process itself.
in_ns() { ip netns exec "$NS" "$@"; }

can_connect() {
    in_ns python3 -c 'import socket, sys
socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1).close()' "$1" "$2" 2>/dev/null
}

cannot_connect() { ! can_connect "$@"; }

fail() {
    echo "FAIL: $*"
    echo "--- fwknopd log"
    cat "$WORK/fwknopd.log" 2>/dev/null || true
    echo "--- ruleset"
    in_ns nft list ruleset 2>/dev/null || true
    exit 1
}

# Retries a check for up to 15 seconds.
wait_for() {
    local what=$1
    shift
    for _ in $(seq 1 75); do
        if "$@"; then return 0; fi
        sleep 0.2
    done
    fail "timed out waiting for: $what"
}

listen() {
    ip netns exec "$NS" python3 -c 'import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(family)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
while True:
    s.accept()[0].close()' "$1" "$2" &
    PIDS+=($!)
}

knock() {
    in_ns "$BIN_DIR/fwknop" --no-rc-file -D "$1" -a "$1" -A "tcp/$SVC_PORT" \
        --key "$KEY" --key-hmac "$HMAC_KEY" || fail "knock to $1"
}

start_fwknopd() {
    cat > "$WORK/server.yaml" <<EOF
udp_port: $SPA_PORT
bind_address: "0.0.0.0"
log_file: ""
syslog_identity: ""
max_spa_packet_age: 120
action_template: $REPO/conf_files/actions/$1.yaml
EOF
    cat > "$WORK/access.yaml" <<EOF
- source: ANY
  open_ports: [tcp/$SVC_PORT]
  key: $KEY
  hmac_key: $HMAC_KEY
  access_timeout: $ACCESS_TIMEOUT
EOF
    ip netns exec "$NS" "$BIN_DIR/fwknopd" -c "$WORK/server.yaml" -a "$WORK/access.yaml" -f -v \
        > "$WORK/fwknopd.log" 2>&1 &
    FWKNOPD=$!
    PIDS+=("$FWKNOPD")
    wait_for "fwknopd to start" grep -q "UDP server listening" "$WORK/fwknopd.log"
}

stop_fwknopd() {
    kill -TERM "$FWKNOPD"
    wait "$FWKNOPD" || fail "fwknopd exited with an error"
    grep -q "shutting down" "$WORK/fwknopd.log" || fail "no shutdown in the log"
}

new_namespace() {
    delete_namespace
    PIDS=()
    ip netns add "$NS"
    in_ns ip link set lo up
}

# A default-drop firewall that lets in replies and SPA packets only. Loopback
# is filtered like any interface, so the test can knock on 127.0.0.1.
nftables_base() {
    in_ns nft -f - <<EOF
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        udp dport $SPA_PORT accept
    }
}
EOF
}

iptables_base() {
    in_ns iptables -P INPUT DROP
    in_ns iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    in_ns iptables -A INPUT -p udp --dport "$SPA_PORT" -j ACCEPT
}

nft_rule_count() {
    in_ns nft list chain inet filter fwknop_input 2>/dev/null | grep -c "fwknop-$1-tcp-$SVC_PORT" || true
}

ipt_rule_count() {
    in_ns iptables -S FWKNOP_INPUT 2>/dev/null | grep -c -- "-s $1/32 .*--dport $SVC_PORT" || true
}

open_then_close() {
    local ip=$1 count=$2
    cannot_connect "$ip" "$SVC_PORT" || fail "$ip:$SVC_PORT is reachable before the knock"
    knock "$ip"
    wait_for "$ip:$SVC_PORT to open" can_connect "$ip" "$SVC_PORT"
    [[ $($count "$ip") == 1 ]] || fail "expected one rule for $ip"
    wait_for "$ip:$SVC_PORT to close after ${ACCESS_TIMEOUT}s" cannot_connect "$ip" "$SVC_PORT"
    [[ $($count "$ip") == 0 ]] || fail "the rule for $ip was not removed"
    echo "  ok: $ip opened, then closed"
}

second_knock_does_not_duplicate() {
    local ip=$1 count=$2
    knock "$ip"
    wait_for "$ip:$SVC_PORT to open" can_connect "$ip" "$SVC_PORT"
    knock "$ip"
    wait_for "the refresh" grep -q "Rule already open for $ip/tcp/$SVC_PORT" "$WORK/fwknopd.log"
    [[ $($count "$ip") == 1 ]] || fail "a second knock added a duplicate rule for $ip"
    echo "  ok: a second knock refreshed the rule"
}

test_nftables() {
    echo "nftables:"
    new_namespace
    nftables_base
    listen 127.0.0.1 "$SVC_PORT"
    listen ::1 "$SVC_PORT"
    start_fwknopd nftables
    in_ns nft list chain inet filter input | grep -q "jump fwknop_input" \
        || fail "init did not add the jump to fwknop_input"

    open_then_close 127.0.0.1 nft_rule_count
    open_then_close ::1 nft_rule_count
    second_knock_does_not_duplicate 127.0.0.1 nft_rule_count

    stop_fwknopd
    cannot_connect 127.0.0.1 "$SVC_PORT" || fail "the port is still open after shutdown"
    if in_ns nft list chain inet filter fwknop_input > /dev/null 2>&1; then
        fail "shutdown left the fwknop_input chain"
    fi
    if in_ns nft list chain inet filter input | grep -q fwknop_input; then
        fail "shutdown left the jump to fwknop_input"
    fi
    in_ns nft list chain inet filter input | grep -q "udp dport $SPA_PORT accept" \
        || fail "shutdown changed the base ruleset"
    echo "  ok: shutdown removed the jump and the chain, and nothing else"
}

test_iptables() {
    echo "iptables:"
    new_namespace
    iptables_base
    listen 127.0.0.1 "$SVC_PORT"
    start_fwknopd iptables

    open_then_close 127.0.0.1 ipt_rule_count
    second_knock_does_not_duplicate 127.0.0.1 ipt_rule_count

    stop_fwknopd
    cannot_connect 127.0.0.1 "$SVC_PORT" || fail "the port is still open after shutdown"
    if in_ns iptables -S FWKNOP_INPUT > /dev/null 2>&1; then
        fail "shutdown left the FWKNOP_INPUT chain"
    fi
    in_ns iptables -S INPUT | grep -q -- "-P INPUT DROP" || fail "shutdown changed the INPUT policy"
    echo "  ok: shutdown removed the FWKNOP_INPUT chain, and nothing else"
}

[[ $(id -u) == 0 ]] || { echo "run as root (sudo)"; exit 1; }
for tool in ip nft iptables python3; do
    command -v "$tool" > /dev/null || { echo "missing $tool"; exit 1; }
done

test_nftables
test_iptables
echo "all firewall tests passed"
