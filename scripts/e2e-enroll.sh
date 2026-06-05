#!/usr/bin/env bash
# Single-use PSK enrollment test (run on the Linux build host).
#
# Proves PSK knock mode: a one-time token (no registered asymmetric key) opens
# the cloaked port via an HMAC-authenticated knock, and is then burned — a second
# knock with the same token is rejected.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-enroll-test
PORT=9999
KNOCK_PORT=62201
GW=10.206.0.1
GATE=10.206.0.2
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

echo "== gate key + one-time token =="
( cd "$WORK" && "$CLI" keygen legit >/dev/null && "$CLI" gen-token tok >/dev/null )
# gated.toml: gate crypto + protected ports + the one-time token. No [[client]].
cat > "$WORK/gated.toml" <<EOF
interface = "veth1"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 1000
skew_seconds = 30
protected_ports = [$PORT]
$(grep -E '^(suite|gate_private_hex|gate_id_hex)' "$WORK/legit.gate.toml")
EOF
cat "$WORK/tok.token.toml" >> "$WORK/gated.toml"

sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

connect() { timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions =="
assert "no knock is cloaked" BLOCKED "$(connect)"
"$CLI" enroll-knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" "$WORK/tok.enroll" >/dev/null; sleep 0.4
assert "one-time token opens the port" CONNECTED "$(connect)"
sleep 1.5  # let the grant expire
"$CLI" enroll-knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" "$WORK/tok.enroll" >/dev/null; sleep 0.4
assert "reused token is rejected (burned)" BLOCKED "$(connect)"
assert "exactly one enrollment accepted" 1 "$(grep -c '"outcome":"open"' "$WORK/gated.log")"
assert "reused token logged UnknownClient" 1 "$(grep -c UnknownClient "$WORK/gated.log")"

echo "== daemon decisions =="; grep '"event":"knock"' "$WORK/gated.log" | sed 's/^/  /'
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
