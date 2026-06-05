#!/usr/bin/env bash
# Knock-port DoS hygiene test (run on the Linux build host).
#
# Proves the XDP pre-filters protect the daemon's crypto path:
#   - a 30-packet flood from one source is rate-limited to ~RATE_LIMIT before it
#     reaches userland (without limiting, all 30 would be processed);
#   - undersized knocks are dropped in-kernel (never reach the daemon);
#   - a legit knock still gets through after the window resets.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-rl-test
PORT=9999
KNOCK_PORT=62201
GW=10.204.0.1
GATE=10.204.0.2
FAILS=0

CLI="$ROOT/target/debug/spa-client"
GATED="$ROOT/spa-gated/target/debug/spa-gated"
OBJ="$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"

sudo pkill -9 -f spa-gated 2>/dev/null
sudo ip netns del "$NS" 2>/dev/null
sudo ip link del veth0 2>/dev/null

WORK="$(mktemp -d)"
cleanup() {
  sudo pkill -9 -f "spa-gated $WORK" 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del veth0 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
( cd "$ROOT/spa-ebpf" && cargo build --release ) || exit 1
( cd "$ROOT" && cargo build -p spa-client ) || exit 1
( cd "$ROOT/spa-gated" && cargo build ) || exit 1

echo "== netns + daemon =="
sudo ip netns add "$NS"
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns "$NS"
sudo ip addr add "$GW/24" dev veth0 && sudo ip link set veth0 up
sudo ip netns exec "$NS" ip addr add "$GATE/24" dev veth1
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip link set lo up

( cd "$WORK" && "$CLI" keygen legit >/dev/null )
cat > "$WORK/gated.toml" <<EOF
interface = "veth1"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 1000
skew_seconds = 30
protected_ports = [$PORT]
EOF
cat "$WORK/legit.gate.toml" >> "$WORK/gated.toml"

cat > "$WORK/flood.py" <<'PY'
import socket, sys
host, port, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(n):
    s.sendto(b"x" * size, (host, port))
PY

sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

seen() { grep -c Undecryptable "$WORK/gated.log"; }
assert_le() { if [ "$2" -le "$3" ]; then echo "  PASS: $1 ($2 <= $3)"; else echo "  FAIL: $1 ($2 > $3)"; FAILS=$((FAILS + 1)); fi; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions (RATE_LIMIT = 10/source/sec) =="
# Flood 30 valid-sized junk packets from one source in a burst.
python3 "$WORK/flood.py" "$GATE" "$KNOCK_PORT" 30 200; sleep 0.5
assert_le "flood of 30 rate-limited at the source" "$(seen)" 13

# Undersized knocks are dropped in-kernel: count must not move.
sleep 1.2
BEFORE=$(seen)
python3 "$WORK/flood.py" "$GATE" "$KNOCK_PORT" 8 20; sleep 0.5
assert "undersized knocks dropped in-kernel" "$BEFORE" "$(seen)"

# A legit knock after the window resets is still accepted.
sleep 1.2
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null; sleep 0.5
assert "legit knock still accepted after flood" 1 "$(grep -c OPEN "$WORK/gated.log")"

if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
