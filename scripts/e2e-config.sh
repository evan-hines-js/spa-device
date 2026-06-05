#!/usr/bin/env bash
# Signed config bundle test (run on the Linux build host).
#
# Proves the bundle path: a client authorized by bundle gen 1 connects; after a
# gen 2 bundle that revokes it is hot-reloaded, the same client is denied; a
# rolled-back (older-generation) bundle is ignored (anti-rollback); and a bundle
# signed by the wrong key is rejected.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-cfg-test
PORT=9999
KNOCK_PORT=62201
GW=10.203.0.1
GATE=10.203.0.2
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

cd "$WORK"
"$CLI" keygen legit >/dev/null
ANCHOR_PUB=$("$CLI" gen-anchor cp | grep anchor_pubkey_hex | cut -d= -f2)
grep -A3 '^\[\[client\]\]' legit.gate.toml > legit-client.block

make_bundle() { # generation client-block-file out
  { echo "generation = $1"; echo "protected_ports = [$PORT]"; echo ""; cat "$2"; } > "$WORK/payload.toml"
  "$CLI" sign-bundle "$WORK/cp.anchor.key" "$WORK/payload.toml" "$3" >/dev/null
}
empty_block=/dev/null

# bundle gen 1 authorizes legit
make_bundle 1 legit-client.block "$WORK/policy.bundle"

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
knock() { "$CLI" knock "$GATE:$KNOCK_PORT" "$WORK/legit.knock" >/dev/null; sleep 0.4; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions =="
knock
assert "gen1: authorized client connects" CONNECTED "$(connect)"

# gen 2 revokes the client (empty client set)
make_bundle 2 "$empty_block" "$WORK/policy.bundle"; sleep 3
sleep 2  # let gen1's grant expire
knock
assert "gen2 hot-reload revokes the client" BLOCKED "$(connect)"

# rollback to gen 1 must be ignored (anti-rollback)
make_bundle 1 legit-client.block "$WORK/policy.bundle"; sleep 3
knock
assert "rolled-back (older) bundle is ignored" BLOCKED "$(connect)"

# a bundle signed by the wrong anchor must be rejected
"$CLI" gen-anchor evil >/dev/null
make_bundle 3 legit-client.block "$WORK/policy.bundle.tmp"
"$CLI" sign-bundle "$WORK/evil.anchor.key" "$WORK/payload.toml" "$WORK/policy.bundle" >/dev/null
sleep 3
knock
assert "wrong-anchor bundle is rejected" BLOCKED "$(connect)"

assert "applied generation 2" 1 "$(grep -c '"action":"applied"' "$WORK/gated.log")"
assert "ignored the rollback" 1 "$(grep -c '"action":"ignored"' "$WORK/gated.log")"
assert "rejected the wrong-anchor bundle" 1 "$(grep -c '"action":"rejected"' "$WORK/gated.log")"

echo "== bundle log =="; grep '"event":"bundle"' "$WORK/gated.log" | sed 's/^/  /'
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
