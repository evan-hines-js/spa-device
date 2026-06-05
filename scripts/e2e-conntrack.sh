#!/usr/bin/env bash
# Conntrack-handoff test (run on the Linux build host).
#
# Proves an established connection outlives the micro-pinhole: with a 1s pinhole,
# a ~6s slow download started right after a knock must complete in full (the flow
# table keeps it alive after the grant expires), while a NEW connection started
# after the pinhole is dropped (proving the pinhole really closed).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-ct-test
PORT=9999
KNOCK_PORT=62201
GW=10.201.0.1
GATE=10.201.0.2
FAILS=0
SIZE=300000

CLI="$ROOT/target/debug/spa-client"
GATED="$ROOT/spa-gated/target/debug/spa-gated"
OBJ="$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"

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

echo "== netns + cloaked listener (serving a $SIZE-byte file) =="
mkdir -p "$WORK/served"
head -c "$SIZE" /dev/urandom > "$WORK/served/big.bin"
sudo ip netns add "$NS"
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns "$NS"
sudo ip addr add "$GW/24" dev veth0 && sudo ip link set veth0 up
sudo ip netns exec "$NS" ip addr add "$GATE/24" dev veth1
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" bash -c "cd '$WORK/served' && python3 -m http.server $PORT --bind $GATE" >/dev/null 2>&1 &
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

assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions (pinhole = 1s) =="
# Knock, then immediately start a ~6s download (50 KB/s) that spans the pinhole.
"$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null
curl --limit-rate 50k -s --max-time 30 -o "$WORK/out.bin" "http://$GATE:$PORT/big.bin"
GOT=$(stat -c %s "$WORK/out.bin" 2>/dev/null || echo 0)
assert "slow download survives pinhole close" "$SIZE" "$GOT"

# Pinhole closed long ago now; a new connection (no re-knock) must be dropped.
NEW=$(timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED)
assert "new connection after pinhole is cloaked" BLOCKED "$NEW"
assert "exactly one knock accepted" 1 "$(grep -c 'OPEN' "$WORK/gated.log")"

echo "== daemon decisions =="; grep -E "OPEN|DENY" "$WORK/gated.log" | sed 's/^/  /'
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
