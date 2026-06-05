#!/usr/bin/env bash
# Client agent (TUN) end-to-end (run on the Linux build host).
#
# Proves the workstation experience: reach a cloaked service by its mesh IP with
# no hand-run knock. A real spa-gated cloaks :9999 in a netns; the agent runs on
# the host with a TUN, pulls a (mock) signed catalog, routes the mesh CIDR, and
# per flow knocks the gate + forwards. `curl http://<mesh_ip>:9999` then connects
# through the dark port. The mock control plane stands in for Argus over HTTPS.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=spa-agent-test
SVC=9999
KNOCK_PORT=62201
CP_PORT=8443
MESH_IP=100.64.0.1
GW=10.212.0.1
GATE=10.212.0.2
FAILS=0

CLI="$ROOT/target/debug/spa-client"
AGENT="$ROOT/target/debug/spa-agent"
GATED="$ROOT/spa-gated/target/debug/spa-gated"
OBJ="$ROOT/spa-ebpf/target/bpfel-unknown-none/release/spa-gate"

sudo pkill -9 -f spa-agent 2>/dev/null
sudo pkill -9 -f spa-gated 2>/dev/null
sudo pkill -f "catmock.py" 2>/dev/null
sudo ip netns del "$NS" 2>/dev/null
sudo ip link del vethH 2>/dev/null

WORK="$(mktemp -d)"
cleanup() {
  sudo pkill -9 -f "spa-agent up" 2>/dev/null
  "$AGENT" down >/dev/null 2>&1
  sudo pkill -9 -f "spa-gated $WORK" 2>/dev/null
  pkill -f "$WORK/catmock.py" 2>/dev/null
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del vethH 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
( cd "$ROOT/spa-ebpf" && cargo build --release ) || exit 1
( cd "$ROOT" && cargo build -p spa-client -p spa-agent ) || exit 1
( cd "$ROOT/spa-gated" && cargo build ) || exit 1

echo "== netns + cloaked service =="
sudo ip netns add "$NS"
sudo ip link add vethH type veth peer name vethG
sudo ip link set vethG netns "$NS"
sudo ip addr add "$GW/24" dev vethH && sudo ip link set vethH up
sudo ip netns exec "$NS" ip addr add "$GATE/24" dev vethG
sudo ip netns exec "$NS" ip link set vethG up
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" python3 -m http.server "$SVC" --bind "$GATE" >/dev/null 2>&1 &
sleep 1

cd "$WORK"
echo "== gate key + enrolled agent identity =="
"$CLI" keygen gate >/dev/null
PUB=$("$CLI" gen-client agent | grep public_key_hex | cut -d= -f2)
THUMB=$(printf %s "$PUB" | xxd -r -p | sha256sum | cut -d' ' -f1)
GATE_PUB=$(grep '^gate_pubkey_hex=' gate.knock | cut -d= -f2)
GATE_ID=$(grep '^gate_id_hex=' gate.knock | cut -d= -f2)

cat > gated.toml <<EOF
interface = "vethG"
knock_port = $KNOCK_PORT
bpf_object = "$OBJ"
pinhole_ms = 2000
skew_seconds = 30
protected_ports = [$SVC]
$(grep -E '^(suite|gate_private_hex|gate_id_hex)' gate.gate.toml)

[[client]]
thumbprint_hex = "$THUMB"
public_key_hex = "$PUB"
ports = [$SVC]
EOF
sudo ip netns exec "$NS" "$GATED" "$WORK/gated.toml" >"$WORK/gated.log" 2>&1 &
sleep 3

echo "== mock control plane (HTTPS) + catalog =="
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.pem -days 1 -nodes \
  -subj "/CN=Test Control-Plane CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout key.pem -out server.csr -nodes \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 1 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE") >/dev/null 2>&1

cat > catalog.json <<EOF
{ "device": { "name": "test", "thumbprint": "$THUMB" },
  "mesh_cidr": "100.64.0.0/10",
  "services": [
    { "name": "demo-svc", "mesh_ip": "$MESH_IP",
      "endpoints": [
        { "protocol": "tcp", "port": $SVC, "address": "$GATE",
          "descriptor": { "gate_id_hex": "$GATE_ID", "gate_pubkey_hex": "$GATE_PUB",
            "suite": "modern", "address": "$GATE", "knock_port": $KNOCK_PORT } } ] } ] }
EOF

cat > catmock.py <<PY
import http.server, ssl, sys
PORT, CATALOG, CERT, KEY = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        data = open(CATALOG, 'rb').read()
        self.send_response(200); self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
httpd = http.server.HTTPServer(('127.0.0.1', PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
python3 "$WORK/catmock.py" "$CP_PORT" "$WORK/catalog.json" "$WORK/cert.pem" "$WORK/key.pem" &
sleep 1

echo "== agent up (TUN on host) =="
sudo "$AGENT" up "$WORK/agent.client.key" modern "https://127.0.0.1:$CP_PORT" "$WORK/ca.pem" >"$WORK/agent.log" 2>&1 &
sleep 4

echo "== route/iface diag =="
ip -o addr show tun0 2>&1 | sed 's/^/  /'
echo -n "  route: "; ip route get "$MESH_IP" 2>&1 | head -1

connect() { timeout 6 curl --connect-timeout 4 -s -o /dev/null -w "%{http_code}" "http://$MESH_IP:$SVC/" 2>/dev/null; }
assert() { if [ "$2" = "$3" ]; then echo "  PASS: $1"; else echo "  FAIL: $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== assertions =="
assert "agent came up with the service routed" 1 "$(grep -c 'agent up' "$WORK/agent.log")"
CODE="$(connect)"
assert "reach demo-svc by mesh IP through the agent" 200 "$CODE"
assert "gate authorized the agent's knock" 1 "$(grep -c '"outcome":"open"' "$WORK/gated.log")"

echo "== agent log =="; sed 's/^/  /' "$WORK/agent.log" | head -24
echo "== gate log =="; sed 's/^/  /' "$WORK/gated.log" | head -8
echo "== host route to gate =="; ip route get "$GATE" 2>&1 | sed 's/^/  /' | head -1
if [ "$FAILS" -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
