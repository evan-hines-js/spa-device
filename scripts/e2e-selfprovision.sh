#!/usr/bin/env bash
# Gate self-provisioning test (run on the Linux build host).
#
# Proves the daemon provisions itself against the control plane over HTTPS: it
# derives its OWN knock pubkey (so it can't report the wrong one — the bug the
# manual curl/grep flow caused), POSTs it to /api/gate/identity, pulls its signed
# bundle from /api/gate/bundle into a path that didn't exist, and cloaks. A tiny
# python HTTPS server with a self-signed cert (pinned via ca_cert) is the control
# plane. TLS rides our aws-lc-rs rustls provider — no second crypto stack.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-prov-test
PORT=9999
KNOCK_PORT=62201
CP_PORT=8443
GW=10.211.0.1          # host side of the veth = where the mock control plane lives
GATE=10.211.0.2
FAILS=0

CLI="$ROOT/target/debug/spa-client"
GATED="$ROOT/spa-gated/target/debug/spa-gated"
OBJ="$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"

sudo pkill -9 -f spa-gated 2>/dev/null
sudo pkill -f "cpmock.py" 2>/dev/null
sudo ip netns del "$NS" 2>/dev/null
sudo ip link del veth0 2>/dev/null

WORK="$(mktemp -d)"
cleanup() {
  sudo pkill -9 -f "spa-gated $WORK" 2>/dev/null
  pkill -f "$WORK/cpmock.py" 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del veth0 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
( cd "$ROOT/spa-ebpf" && cargo build --release ) || exit 1
( cd "$ROOT" && cargo build -p spa-client ) || exit 1
( cd "$ROOT/spa-gated" && cargo build ) || exit 1

echo "== netns =="
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

echo "== private CA + server leaf (SAN IP:127.0.0.1) =="
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.pem -days 1 -nodes \
  -subj "/CN=Test Control-Plane CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout key.pem -out server.csr -nodes \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 1 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE") >/dev/null 2>&1

echo "== gate key + signed bundle =="
"$CLI" keygen gate >/dev/null
GATE_PUB=$(grep '^gate_pubkey_hex=' gate.knock | cut -d= -f2)     # the gate's REAL knock pubkey
ANCHOR_PUB=$("$CLI" gen-anchor cp | grep anchor_pubkey_hex | cut -d= -f2)
{ echo "generation = 1"; echo "protected_ports = [$PORT]"; } > payload.toml
"$CLI" sign-bundle cp.anchor.key payload.toml policy.bundle >/dev/null

echo "== mock control plane (HTTPS) =="
cat > cpmock.py <<PY
import http.server, ssl, sys
PORT, BUNDLE, IDOUT, CERT, KEY = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # Content-Length framing, so the client never reads to EOF
    def do_POST(self):
        n = int(self.headers.get('content-length', 0))
        open(IDOUT, 'wb').write(self.rfile.read(n))
        body = b'{"ok":true}'
        self.send_response(200); self.send_header('content-length', str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        data = open(BUNDLE, 'rb').read()
        self.send_response(200); self.send_header('content-type', 'application/octet-stream')
        self.send_header('content-length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
httpd = http.server.HTTPServer(('127.0.0.1', PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
# Run the mock inside the gate's netns (loopback) so the daemon reaches it directly.
sudo ip netns exec "$NS" python3 "$WORK/cpmock.py" "$CP_PORT" "$WORK/policy.bundle" "$WORK/identity.json" "$WORK/cert.pem" "$WORK/key.pem" &
sleep 1

# gated.toml: control_plane drives register + fetch. bundle_path does NOT exist yet.
cat > gated.toml <<EOF
interface = "veth1"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 1000
skew_seconds = 30
config_anchor_hex = "$ANCHOR_PUB"
bundle_path = "$WORK/fetched.bundle"
$(grep -E '^(suite|gate_private_hex|gate_id_hex)' gate.gate.toml)

[control_plane]
url = "https://127.0.0.1:$CP_PORT"
gate_token = "test-token"
address = "$GATE"
ca_cert = "$WORK/ca.pem"
EOF

sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

connect() { timeout 4 curl --connect-timeout 3 -s -o /dev/null "http://$GATE:$PORT/" && echo CONNECTED || echo BLOCKED; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions =="
assert "daemon registered its identity" 1 "$(grep -c '"action":"registered"' "$WORK/gated.log")"
assert "daemon fetched its bundle" 1 "$(grep -c '"action":"bundle-fetched"' "$WORK/gated.log")"
REPORTED=$(grep -o '"public_key_hex":"[0-9a-f]*"' "$WORK/identity.json" | cut -d'"' -f4)
assert "reported the CORRECT gate pubkey" "$GATE_PUB" "$REPORTED"
assert "bundle was pulled to disk" present "$([ -s "$WORK/fetched.bundle" ] && echo present || echo absent)"
assert "port is cloaked after self-provision" BLOCKED "$(connect)"

echo "== raw daemon log =="; sed 's/^/  /' "$WORK/gated.log"
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
