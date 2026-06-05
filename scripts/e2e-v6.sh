#!/usr/bin/env bash
# IPv6 cloaking test (run on the Linux build host).
#
# Same property as e2e-cloak, over IPv6: a v6 TCP service behind an XDP-cloaked
# interface is dropped by default, and only a valid v6 knock opens it.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-v6-test
PORT=9999
KNOCK_PORT=62201
GW=fd00:11::1
GATE=fd00:11::2
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

echo "== netns + cloaked IPv6 listener =="
sudo ip netns add "$NS"
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns "$NS"
sudo ip -6 addr add "$GW/64" dev veth0 nodad && sudo ip link set veth0 up
sudo ip netns exec "$NS" ip -6 addr add "$GATE/64" dev veth1 nodad
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip link set lo up
sleep 1  # let addresses settle
sudo ip netns exec "$NS" python3 -m http.server "$PORT" --bind "$GATE" >/dev/null 2>&1 &
sleep 1

( cd "$WORK" && "$CLI" keygen legit >/dev/null )
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

connect() { timeout 4 curl -g --connect-timeout 3 -s -o /dev/null "http://[$GATE]:$PORT/" && echo CONNECTED || echo BLOCKED; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions (IPv6) =="
assert "no knock is cloaked (v6)" BLOCKED "$(connect)"
"$CLI" knock "[$GATE]:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null; sleep 0.5
assert "valid v6 knock opens the port" CONNECTED "$(connect)"
assert "daemon accepted one v6 knock" 1 "$(grep -c OPEN "$WORK/gated.log")"

echo "== daemon decisions =="; grep -E "OPEN|DENY" "$WORK/gated.log" | sed 's/^/  /'
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
