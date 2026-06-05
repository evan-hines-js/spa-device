#!/usr/bin/env bash
# Signed-bundle enrollment-token test (run on the Linux build host).
#
# Proves one-time PSK tokens carried IN the signed bundle (not just local
# config): a token in bundle gen 1 opens the cloaked port and is burned on reuse;
# a gen 2 bundle that drops that token and adds a fresh one hot-reloads, so the
# old token stays dead and the new one works (tokens follow the bundle's
# anti-rollback hot-reload, same as clients/ports).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-btok-test
PORT=9999
KNOCK_PORT=62201
GW=10.207.0.1
GATE=10.207.0.2
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

echo "== gate key + anchor + two one-time tokens =="
cd "$WORK"
"$CLI" keygen legit >/dev/null
"$CLI" gen-token tok1 >/dev/null
"$CLI" gen-token tok2 >/dev/null
ANCHOR_PUB=$("$CLI" gen-anchor cp | grep anchor_pubkey_hex | cut -d= -f2)

make_bundle() { # generation token-block-file out
  { echo "generation = $1"; echo "protected_ports = [$PORT]"; echo ""; cat "$2"; } > "$WORK/payload.toml"
  "$CLI" sign-bundle "$WORK/cp.anchor.key" "$WORK/payload.toml" "$3" >/dev/null
}

# bundle gen 1 carries tok1
make_bundle 1 "$WORK/tok1.token.toml" "$WORK/policy.bundle"

# gated.toml: only gate crypto + the signed bundle. No inline tokens/clients.
cat > "$WORK/gated.toml" <<EOF
interface = "veth1"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 1000
skew_seconds = 30
config_anchor_hex = "$ANCHOR_PUB"
bundle_path = "$WORK/policy.bundle"
$(grep -E '^(suite|gate_private_hex|gate_id_hex)' legit.gate.toml)
EOF

sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

connect() { timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED; }
enroll() { "$CLI" enroll-knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" "$1" >/dev/null; sleep 0.4; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions =="
assert "no knock is cloaked" BLOCKED "$(connect)"
enroll "$WORK/tok1.enroll"
assert "in-bundle token opens the port" CONNECTED "$(connect)"
sleep 1.5  # let the grant expire
enroll "$WORK/tok1.enroll"
assert "reused in-bundle token is burned" BLOCKED "$(connect)"

# gen 2 drops tok1, adds tok2 (hot-reload)
make_bundle 2 "$WORK/tok2.token.toml" "$WORK/policy.bundle"; sleep 3
enroll "$WORK/tok1.enroll"
assert "dropped token stays dead after reload" BLOCKED "$(connect)"
sleep 1.5
enroll "$WORK/tok2.enroll"
assert "new in-bundle token works after reload" CONNECTED "$(connect)"

assert "applied generation 2" 1 "$(grep -c '"action":"applied"' "$WORK/gated.log")"
assert "two enrollments accepted total" 2 "$(grep -c '"outcome":"open"' "$WORK/gated.log")"

echo "== daemon decisions =="; grep -E '"event":"(knock|bundle)"' "$WORK/gated.log" | sed 's/^/  /'
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
