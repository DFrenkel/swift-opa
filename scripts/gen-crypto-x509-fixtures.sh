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

# RegoValue cannot hold big integers losslessly (Int64/Decimal backed), so this
# round emits SerialNumber and the RSA/ECDSA key components as decimal strings.
# Python's json keeps them as exact ints, so convert those fields here. Reverse
# this transform (and regenerate) once RegoNumber gains arbitrary precision.
BIG_INT_FIELDS = {"SerialNumber", "N", "X", "Y"}

def stringify_big_ints(node):
    if isinstance(node, list):
        return [stringify_big_ints(x) for x in node]
    if isinstance(node, dict):
        return {
            k: (str(v) if k in BIG_INT_FIELDS and isinstance(v, int) else stringify_big_ints(v))
            for k, v in node.items()
        }
    return node

want = stringify_big_ints(want)
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
