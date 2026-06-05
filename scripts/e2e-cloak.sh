#!/usr/bin/env bash
# End-to-end cloaking test (run on the Linux build host).
#
# Stands up a real TCP listener behind an XDP-cloaked interface in a network
# namespace, then asserts the security properties that matter:
#   - the port is dropped by default (cloaked);
#   - garbage, an unregistered client, and an attacker's own keys are all DENIED
#     and leave the port closed;
#   - only a valid, provisioned knock opens it.
#
# Exits non-zero if any assertion fails. Builds the binaries first.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-cloak-test
PORT=9999
KNOCK_PORT=62201
GW=10.200.0.1     # client side (default ns)
GATE=10.200.0.2   # gate side (in the ns)
FAILS=0

CLI="$ROOT/target/debug/spa-client"
GATED="$ROOT/spa-gated/target/debug/spa-gated"
OBJ="$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"
# Clear leftovers from a prior aborted run BEFORE allocating $WORK.
sudo pkill -f spa-gated 2>/dev/null
sudo pkill -f "http.server $PORT" 2>/dev/null
sudo ip netns del "$NS" 2>/dev/null
sudo ip link del veth0 2>/dev/null

WORK="$(mktemp -d)"
cleanup() {
  sudo pkill -f "spa-gated $WORK" 2>/dev/null
  sudo pkill -f "http.server $PORT" 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del veth0 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
( cd "$ROOT/spa-ebpf" && cargo build --release ) || exit 1
( cd "$ROOT" && cargo build -p spa-client ) || exit 1
( cd "$ROOT/spa-gated" && cargo build ) || exit 1

echo "== netns + cloaked listener =="
sudo ip netns add "$NS"
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns "$NS"
sudo ip addr add "$GW/24" dev veth0 && sudo ip link set veth0 up
sudo ip netns exec "$NS" ip addr add "$GATE/24" dev veth1
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" python3 -m http.server "$PORT" --bind "$GATE" >/dev/null 2>&1 &
sleep 1

echo "== keys =="
( cd "$WORK" && "$CLI" keygen legit >/dev/null && "$CLI" keygen attacker >/dev/null )
# hybrid = real gate key (decryptable) + an unregistered client key (untrusted)
{ grep gate_pubkey_hex "$WORK/legit.knock"
  grep gate_id_hex     "$WORK/legit.knock"
  grep client_pkcs8_hex "$WORK/attacker.knock"
  grep "^port="        "$WORK/legit.knock"
  echo "suite=modern"
} > "$WORK/hybrid.knock"

cat > "$WORK/gated.toml" <<EOF
interface = "veth1"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 30000
skew_seconds = 30
protected_ports = [$PORT]
EOF
cat "$WORK/legit.gate.toml" >> "$WORK/gated.toml"

cat > "$WORK/garbage.py" <<'PY'
import socket, sys
# 200 bytes: passes the XDP size pre-filter so it reaches the daemon and is
# rejected there as Undecryptable (undersized junk is dropped in-kernel instead).
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"\x00" * 200, (sys.argv[1], int(sys.argv[2])))
PY

echo "== start daemon =="
sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

connect() { timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED; }
assert() { # label expected actual
  if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi
}

echo "== assertions =="
assert "no knock is cloaked"                 BLOCKED   "$(connect)"
python3 "$WORK/garbage.py" "$GATE" "$KNOCK_PORT"; sleep 0.5
assert "garbage does not open"               BLOCKED   "$(connect)"
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/hybrid.knock" >/dev/null; sleep 0.5
assert "unregistered client does not open"   BLOCKED   "$(connect)"
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/attacker.knock" >/dev/null; sleep 0.5
assert "wrong-gate knock does not open"       BLOCKED   "$(connect)"
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null; sleep 0.5
assert "valid knock opens the port"          CONNECTED "$(connect)"

# decision-log assertions (garbage + wrong-gate => 2 Undecryptable, hybrid => 1
# UnknownClient, valid => 1 OPEN)
assert "two Undecryptable denials"      2 "$(grep -c 'Undecryptable' "$WORK/gated.log")"
assert "one UnknownClient denial"       1 "$(grep -c 'UnknownClient' "$WORK/gated.log")"
assert "one OPEN"                        1 "$(grep -c 'OPEN' "$WORK/gated.log")"

echo "== daemon decisions =="
grep -E "OPEN|DENY" "$WORK/gated.log" | sed 's/^/  /'

if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
