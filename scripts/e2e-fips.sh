#!/usr/bin/env bash
# FIPS-suite end-to-end test (run on the Linux build host).
#
# Proves the FIPS cipher suite (ECDH P-256 / AES-256-GCM / ECDSA P-256) works the
# whole way through: keygen, persistence, daemon, knock, and the TCP cloak.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-fips-test
PORT=9999
KNOCK_PORT=62201
GW=10.205.0.1
GATE=10.205.0.2
FAILS=0

CLI="$ROOT/target/debug/spa-client"
GATED="$ROOT/spa-gated/target/debug/spa-gated"
OBJ="$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"

sudo pkill -9 -f spa-gated 2>/dev/null
sudo pkill -f "http.server $PORT" 2>/dev/null
sudo ip netns del "$NS" 2>/dev/null
sudo ip link del veth0 2>/dev/null

WORK="$(mktemp -d)"
cleanup() {
  sudo pkill -9 -f "spa-gated $WORK" 2>/dev/null
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

echo "== FIPS keys =="
( cd "$WORK" && "$CLI" keygen legit fips >/dev/null )
grep -q 'suite = "fips"' "$WORK/legit.gate.toml" || { echo "  FAIL: keygen did not emit fips"; exit 1; }
cat > "$WORK/gated.toml" <<EOF
interface = "veth1"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 30000
skew_seconds = 30
protected_ports = [$PORT]
EOF
cat "$WORK/legit.gate.toml" >> "$WORK/gated.toml"

sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

connect() { timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions (suite = fips) =="
assert "no knock is cloaked" BLOCKED "$(connect)"
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null; sleep 0.5
assert "valid FIPS knock opens the port" CONNECTED "$(connect)"
assert "daemon accepted one FIPS knock" 1 "$(grep -c OPEN "$WORK/gated.log")"

echo "== daemon decisions =="; grep -E "OPEN|DENY" "$WORK/gated.log" | sed 's/^/  /'
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
