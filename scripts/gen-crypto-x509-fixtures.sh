#!/usr/bin/env bash
# Regenerates crypto.x509 golden fixtures from the real opa binary.
#
# Each fixture is { "input": <pem-or-b64 string>, "want": <opa result value> }.
# Inputs live in Fixtures/cryptox509/inputs/<name>.pem. The `want` is whatever
# OPA returns for the matching builtin, captured verbatim.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)/Tests/RegoTests/BuiltinTests/Fixtures/cryptox509"
inputs="$here/inputs"

emit() { # <name> <builtin>
  local name="$1" builtin="$2"
  python3 - "$name" "$inputs/$name.pem" "$here/$name.json" "$builtin" <<'PY'
import json, subprocess, sys
name, path, out, builtin = sys.argv[1:5]
inp = open(path).read().strip()
query = f'{builtin}(input)'
proc = subprocess.run(
    ["opa", "eval", "-f", "json", "--stdin-input", query],
    input=json.dumps(inp), capture_output=True, text=True,
)
if proc.returncode != 0:
    sys.exit(f"opa failed for {name}: {proc.stderr}")
want = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
json.dump({"input": inp, "want": want}, open(out, "w"), indent=2, sort_keys=True)
print(f"wrote {name}.json")
PY
}

emit rsa-leaf       crypto.x509.parse_certificates
emit ecdsa-leaf     crypto.x509.parse_certificates
emit ed25519-leaf   crypto.x509.parse_certificates
emit rsa-1024-chain crypto.x509.parse_certificates
emit chain          crypto.x509.parse_certificates
emit csr            crypto.x509.parse_certificate_request

echo "fixtures written to $here"
