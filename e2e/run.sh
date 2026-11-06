#!/usr/bin/env bash
# Run on a disposable VM as root. No endpoint overrides or disabled TLS verification.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo 'e2e/run.sh needs root on a disposable VM to bind :443 and edit /etc/hosts.' >&2
  exit 1
fi
if [[ $# -gt 1 || ( $# -eq 1 && $1 != --health-only ) ]]; then
  echo 'usage: bash e2e/run.sh [--health-only]' >&2
  exit 2
fi
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cache_root=${XDG_CACHE_HOME:-${HOME}/.cache}/segredium
mkdir -p "$cache_root"
run_dir=$(mktemp -d "$cache_root/e2e.XXXXXXXX")
server_pid=
hosts_saved=false
trust_file=
client_dir=
owner_a=
owner_b=
cleanup() {
  result=$?
  trap - EXIT
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if $hosts_saved; then
    cat "$run_dir/hosts.before" > /etc/hosts
    cmp "$run_dir/hosts.before" /etc/hosts
  fi
  if [[ -n $trust_file ]]; then
    rm -f "$trust_file"
    update-ca-certificates > "$run_dir/trust-cleanup.log" 2>&1
  fi
  if [[ -n $owner_a ]]; then userdel "$owner_a"; fi
  if [[ -n $owner_b ]]; then userdel "$owner_b"; fi
  if [[ -n $client_dir ]]; then
    rm -f "$client_dir/ca.pem"
    rmdir "$client_dir"
  fi
  if [[ $result -ne 0 ]]; then
    echo "e2e failed; server log follows, artifacts: $run_dir" >&2
    cat "$run_dir/server.log" >&2 || true
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$repo"
for command in go python3 curl update-ca-certificates; do
  command -v "$command" >/dev/null
done
if [[ ${1:-} != --health-only ]]; then
  aws --version
  python3 -c 'import boto3; print("boto3", boto3.__version__)'
fi
go build -trimpath -ldflags='-s -w' -o "$run_dir/segredium" ./cmd/segredium

# Isolate CA and persistence so repeated runs leave host data untouched.
unset SEGREDIUM_CONFIG SEGREDIUM_HTTPS_ADDR SEGREDIUM_HTTP_ADDR SEGREDIUM_TLS_MODE
unset SEGREDIUM_AUTH_MODE SEGREDIUM_STORAGE_BACKEND SEGREDIUM_DEFAULT_REGION
unset SEGREDIUM_HTTPS_ADDR_EMPTY SEGREDIUM_HTTP_ADDR_EMPTY
unset SEGREDIUM_STORAGE_KEY_FILE SEGREDIUM_STORAGE_KEY_FILE_EMPTY SEGREDIUM_ACCESS_MODE
unset SEGREDIUM_STORAGE_PURGE_INTERVAL SEGREDIUM_STORAGE_PURGE_INTERVAL_EMPTY
export SEGREDIUM_TLS_CA_DIR="$run_dir/ca"
export SEGREDIUM_STORAGE_PATH="$run_dir/data"
"$run_dir/segredium" serve > "$run_dir/server.log" 2>&1 &
server_pid=$!

cp /etc/hosts "$run_dir/hosts.before"
hosts_saved=true
{
  echo '127.0.0.1 secretsmanager.us-east-1.amazonaws.com secretsmanager.us-west-2.amazonaws.com'
  cat "$run_dir/hosts.before"
} > "$run_dir/hosts.after"
cat "$run_dir/hosts.after" > /etc/hosts

# Proxy settings can route around /etc/hosts. Endpoint settings can bypass the hostnames.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
unset AWS_ENDPOINT_URL AWS_ENDPOINT_URL_SECRETS_MANAGER AWS_PROFILE AWS_SESSION_TOKEN
export NO_PROXY='*' no_proxy='*' AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
export AWS_ACCESS_KEY_ID=segredium-e2e AWS_SECRET_ACCESS_KEY=segredium-e2e
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER='' AWS_MAX_ATTEMPTS=1
export AWS_USE_DUALSTACK_ENDPOINT=false AWS_USE_FIPS_ENDPOINT=false
export AWS_CONFIG_FILE="$run_dir/aws-config" AWS_SHARED_CREDENTIALS_FILE="$run_dir/aws-credentials"
touch "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE"

wait_ready() {
  local ready=false
  for attempt in {1..100}; do
    if [[ -s $run_dir/ca/ca.crt.pem ]] && curl --silent --fail --cacert "$run_dir/ca/ca.crt.pem" \
      https://secretsmanager.us-east-1.amazonaws.com/_segredium/health > "$run_dir/health.json"; then
      ready=true
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo 'server exited before becoming ready' >&2
      exit 1
    fi
    sleep 0.1
  done
  if ! $ready; then
    echo 'server did not become ready on :443' >&2
    exit 1
  fi
}
wait_ready

restart_server() {
  kill "$server_pid"
  wait "$server_pid"
  server_pid=
  "$run_dir/segredium" serve >> "$run_dir/server.log" 2>&1 &
  server_pid=$!
  wait_ready
}

"$run_dir/segredium" ca export > "$run_dir/export.pem"
cmp "$run_dir/export.pem" "$run_dir/ca/ca.crt.pem"
"$run_dir/segredium" ca install-hint > "$run_dir/install-hint.txt"
trust_file="/usr/local/share/ca-certificates/segredium-$(basename "$run_dir").crt"
cp "$run_dir/export.pem" "$trust_file"
update-ca-certificates > "$run_dir/trust-install.log" 2>&1
for region in us-east-1 us-west-2; do
  curl --silent --show-error --fail "https://secretsmanager.$region.amazonaws.com/_segredium/health"
  echo " TLS/system trust/hosts health passed: $region"
done
echo "server idle RSS KiB: $(ps -o rss= -p "$server_pid" | tr -d ' ')"
if [[ ${1:-} == --health-only ]]; then
  exit 0
fi

# AWS CLI/boto3 ship their own CA bundles. Go also reads SSL_CERT_FILE.
export AWS_CA_BUNDLE="$run_dir/export.pem" SSL_CERT_FILE="$run_dir/export.pem"
python3 e2e/clients.py
(
  cd e2e/sdkgo
  # Exercise the Go system trust path rather than AWS_CA_BUNDLE's custom loader.
  unset AWS_CA_BUNDLE
  go run .
)

aws secretsmanager create-secret --region us-east-1 --name e2e-persistence \
  --secret-string before-restart > "$run_dir/persist-create.json"
aws secretsmanager put-secret-value --region us-east-1 --secret-id e2e-persistence \
  --secret-string after-update > "$run_dir/persist-put.json"
aws secretsmanager create-secret --region us-east-1 --name e2e-delete-persistence \
  --secret-string recover-after-restart > "$run_dir/delete-create.json"
aws secretsmanager delete-secret --region us-east-1 --secret-id e2e-delete-persistence \
  --recovery-window-in-days 7 > "$run_dir/delete-scheduled.json"
aws secretsmanager create-secret --region us-east-1 --name e2e-force-persistence \
  --secret-string permanently-removed > "$run_dir/force-create.json"
aws secretsmanager delete-secret --region us-east-1 --secret-id e2e-force-persistence \
  --force-delete-without-recovery > "$run_dir/force-delete.json"
restart_server
python3 - "$run_dir" <<'PY'
import json
import pathlib
import subprocess
import sys

artifacts = pathlib.Path(sys.argv[1])
created = json.loads((artifacts / "persist-create.json").read_text())
updated = json.loads((artifacts / "persist-put.json").read_text())
def get(*args):
    return json.loads(subprocess.check_output([
        "aws", "secretsmanager", "get-secret-value", "--region", "us-east-1",
        "--secret-id", "e2e-persistence", *args], text=True))
current = get()
previous = get("--version-stage", "AWSPREVIOUS")
assert current["SecretString"] == "after-update" and current["VersionId"] == updated["VersionId"]
assert previous["SecretString"] == "before-restart" and previous["VersionId"] == created["VersionId"]
assert current["ARN"] == previous["ARN"] == created["ARN"]
assert get("--version-id", created["VersionId"])["SecretString"] == "before-restart"
print("PASS: encrypted persistence preserves values, version IDs, and stages across restart.")

def call(operation, name, *args, success=True):
    result = subprocess.run(["aws", "secretsmanager", operation, "--region", "us-east-1",
                             "--secret-id", name, *args], text=True, capture_output=True)
    if not success:
        assert result.returncode != 0 and "ResourceNotFoundException" in result.stderr, result
        return
    assert result.returncode == 0, result.stderr
    # The CLI prints nothing for an empty {} response (e.g. force-deleting a missing secret).
    return json.loads(result.stdout) if result.stdout.strip() else {}

scheduled = json.loads((artifacts / "delete-scheduled.json").read_text())
described = call("describe-secret", "e2e-delete-persistence")
assert described["ARN"] == scheduled["ARN"] and "DeletedDate" in described
assert call("restore-secret", "e2e-delete-persistence")["ARN"] == scheduled["ARN"]
assert call("get-secret-value", "e2e-delete-persistence")["SecretString"] == "recover-after-restart"
call("describe-secret", "e2e-force-persistence", success=False)
call("delete-secret", "e2e-force-persistence", "--force-delete-without-recovery")
recreated = json.loads(subprocess.check_output([
    "aws", "secretsmanager", "create-secret", "--region", "us-east-1",
    "--name", "e2e-force-persistence"], text=True))
assert recreated["ARN"] != json.loads((artifacts / "force-create.json").read_text())["ARN"]
print("PASS: deletion survives restart; scheduled secret restores, forced secret stays gone and its name is reusable.")
PY

# Two distinct non-root users prove peer UID lookup rather than root's access bypass.
for command in useradd userdel runuser; do command -v "$command" >/dev/null; done
useradd --no-create-home --shell /usr/sbin/nologin "seg-e2e-a-$$"
owner_a="seg-e2e-a-$$"
useradd --no-create-home --shell /usr/sbin/nologin "seg-e2e-b-$$"
owner_b="seg-e2e-b-$$"
client_dir=$(mktemp -d /run/segredium-e2e.XXXXXXXX)
chmod 0755 "$client_dir"
cp "$run_dir/export.pem" "$client_dir/ca.pem"
chmod 0644 "$client_dir/ca.pem"
export SEGREDIUM_ACCESS_MODE=owner
restart_server
as_user() {
  runuser -u "$1" -- env AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_CA_BUNDLE="$client_dir/ca.pem" SSL_CERT_FILE="$client_dir/ca.pem" \
    aws secretsmanager "${@:2}" --region us-east-1
}
as_user "$owner_a" create-secret --name e2e-owner-a --secret-string owned-value > "$run_dir/owner-create.json"
as_user "$owner_a" get-secret-value --secret-id e2e-owner-a > "$run_dir/owner-get.json"
if as_user "$owner_b" get-secret-value --secret-id e2e-owner-a > "$run_dir/owner-denied.out" 2> "$run_dir/owner-denied.err"; then
  echo 'different Unix user unexpectedly read the secret' >&2
  exit 1
fi
grep -q AccessDeniedException "$run_dir/owner-denied.err"
as_user "$owner_b" list-secrets > "$run_dir/owner-list-b.json"
aws secretsmanager list-secrets --region us-east-1 > "$run_dir/owner-list-root.json"
restart_server
as_user "$owner_a" get-secret-value --secret-id e2e-owner-a > "$run_dir/owner-reopen.json"
python3 - "$run_dir" <<'PY'
import json
import pathlib
import sys

artifacts = pathlib.Path(sys.argv[1])
def read(name):
    return json.loads((artifacts / name).read_text())
assert read("owner-get.json")["SecretString"] == "owned-value"
assert read("owner-reopen.json")["SecretString"] == "owned-value"
assert "e2e-owner-a" not in {s["Name"] for s in read("owner-list-b.json")["SecretList"]}
assert "e2e-owner-a" in {s["Name"] for s in read("owner-list-root.json")["SecretList"]}
print("PASS: owner UID survives restart; owner reads, another user is denied, root lists it.")
PY
echo "server post-test RSS KiB: $(ps -o rss= -p "$server_pid" | tr -d ' ')"
echo 'PASS: AWS CLI v2, boto3, and aws-sdk-go-v2 via real HTTPS hostnames in both regions.'
