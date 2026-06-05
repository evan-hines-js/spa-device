#!/usr/bin/env bash
# Fail-closed test (run on the Linux build host).
#
# Proves the port stays closed when the daemon dies. With a 1s pinhole: knock and
# connect (works), then kill -9 the daemon so XDP detaches. After the grant has
# expired, a new connection must still be DROPPED by the nftables floor (fail
# closed). Without the floor this would CONNECT (port exposed) — that is the bug
# the floor fixes.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-fc-test
PORT=9999
KNOCK_PORT=62201
GW=10.202.0.1
GATE=10.202.0.2
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

sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

connect() { timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions =="
assert "floor installed" 1 "$(grep -c 'floor installed' "$WORK/gated.log")"
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null; sleep 0.3
assert "valid knock connects" CONNECTED "$(connect)"

# Kill the daemon hard: XDP detaches, nftables floor must remain.
sudo pkill -9 -f "spa-gated $WORK"
sleep 2  # > pinhole, so the allow4 entry has expired
XDP="$(sudo ip netns exec "$NS" ip link show veth1 | grep -c xdp)"
assert "XDP detached after kill -9" 0 "$XDP"
assert "port still cloaked (fail closed)" BLOCKED "$(connect)"

if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
