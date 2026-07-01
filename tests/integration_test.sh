#!/usr/bin/env bash
# End-to-end integration test: builds the consumer binary, generates real
# packages via the actual packager pipeline (tests/generate_integration_fixtures.py),
# provisions device state at the fixed paths in consumer/src/config.h, and
# feeds each package through the real consumer binary - checking exit
# codes against docs/FORMAT_SPEC.md's table.
#
# Must run as root (writes to /etc/fota-secure and /opt/fota-secure) -
# intended for the Docker/CI environment per CLAUDE.md's build
# environment section, not a developer's own machine.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

BUILD_DIR="$WORK_DIR/build"
CONSUMER_BIN="$BUILD_DIR/fota-secure-consumer"
FIXTURES_DIR="$WORK_DIR/fixtures"

VERSION_FILE="/etc/fota-secure/version"
INSTALL_DIR="/opt/fota-secure/install"

pass_count=0
fail_count=0

check_exit_code() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" -eq "$expected" ]; then
        echo "PASS: $description (exit $actual)"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: $description (expected exit $expected, got $actual)"
        fail_count=$((fail_count + 1))
    fi
}

check_condition() {
    local description="$1"
    local condition="$2"
    if [ "$condition" = "true" ]; then
        echo "PASS: $description"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: $description"
        fail_count=$((fail_count + 1))
    fi
}

run_consumer() {
    # Runs the consumer against $1, ignoring its exit code (set -e would
    # otherwise abort the script on the expected-nonzero cases).
    set +e
    "$CONSUMER_BIN" "$1" ${2:+--downgrade-secret "$2"}
    echo $?
    set -e
}

echo "=== building consumer binary via CMake ==="
cmake -S "$REPO_ROOT/consumer" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR"

echo "=== installing packager + generating real packages ==="
python3 -m venv "$WORK_DIR/venv"
"$WORK_DIR/venv/bin/pip" install -q --upgrade pip
"$WORK_DIR/venv/bin/pip" install -q -e "$REPO_ROOT/packager"
"$WORK_DIR/venv/bin/python" "$REPO_ROOT/tests/generate_integration_fixtures.py" \
    --output-dir "$FIXTURES_DIR"

echo "=== provisioning device state ==="
mkdir -p /etc/fota-secure "$INSTALL_DIR"
cp "$FIXTURES_DIR/keys/signing_public.pem" /etc/fota-secure/signing_public.pem
cp "$FIXTURES_DIR/keys/device_private.pem" /etc/fota-secure/device_private.pem
rm -f "$VERSION_FILE" /etc/fota-secure/downgrade_secret.hash
rm -rf "${INSTALL_DIR:?}"/*

echo
echo "=== negative cases (device state untouched, no prior install) ==="

code=$(run_consumer "$FIXTURES_DIR/bad_signature.bin")
check_exit_code "tampered signature -> exit 5" 5 "$code"

code=$(run_consumer "$FIXTURES_DIR/tampered_ciphertext.bin")
check_exit_code "tampered ciphertext caught by signature verify (verify-then-decrypt) -> exit 5" 5 "$code"

code=$(run_consumer "$FIXTURES_DIR/wrong_platform.bin")
check_exit_code "wrong platform tag -> exit 4" 4 "$code"

code=$(run_consumer "$FIXTURES_DIR/path_traversal.bin")
check_exit_code "validly-signed but path-traversal payload -> exit 9 (installer rejects)" 9 "$code"

# Truncated/corrupt blob, per docs/TASKS.md's Phase 3 negative cases.
# Truncating anywhere - even just the header - fails the length check
# before any crypto is attempted, since header/wrapped_key/signature all
# have to be fully present before signature verification can even run.
head -c 30 "$FIXTURES_DIR/valid_v1.bin" > "$WORK_DIR/truncated.bin"
code=$(run_consumer "$WORK_DIR/truncated.bin")
check_exit_code "truncated blob (30 bytes, shorter than the fixed header) -> exit 3" 3 "$code"

# Genuinely valid signature and wrapped key, but wrapped for a different
# device's public key than the one provisioned locally - signature
# verification succeeds (nothing about the package itself is corrupt),
# but unwrapping the AES key with this device's private key fails. This
# is the "corrupt blob" -> exit 8 half of docs/TASKS.md's Phase 3 case:
# in this verify-then-decrypt architecture, truncation/tampering of the
# package itself is always caught upstream (exit 3 or 5, see above) -
# exit 8 is reached only via a real key mismatch, not corruption.
code=$(run_consumer "$FIXTURES_DIR/wrong_device_key.bin")
check_exit_code "valid signature, wrapped for a different device's key -> exit 8" 8 "$code"

remaining=$(find "$INSTALL_DIR" -type f | wc -l)
check_condition "no files installed after any negative case" "$([ "$remaining" -eq 0 ] && echo true || echo false)"

echo
echo "=== positive case: fresh install ==="

code=$(run_consumer "$FIXTURES_DIR/valid_v1.bin")
check_exit_code "valid v1 package, no prior install -> exit 0" 0 "$code"

kernel_content=$(cat "$INSTALL_DIR/kernel.bin" 2>/dev/null || echo "MISSING")
check_condition "kernel.bin installed with v1 content" "$([ "$kernel_content" = "kernel bytes for 1.0.0.0" ] && echo true || echo false)"

version_content=$(cat "$VERSION_FILE" 2>/dev/null || echo "MISSING")
check_condition "version file updated to 1.0.0.0" "$([ "$version_content" = "1.0.0.0" ] && echo true || echo false)"

echo
echo "=== re-install same version ==="

code=$(run_consumer "$FIXTURES_DIR/valid_v1.bin")
check_exit_code "same version again -> exit 2 (up to date)" 2 "$code"

echo
echo "=== upgrade ==="

code=$(run_consumer "$FIXTURES_DIR/valid_v2.bin")
check_exit_code "newer version v2 -> exit 0" 0 "$code"

kernel_content=$(cat "$INSTALL_DIR/kernel.bin" 2>/dev/null || echo "MISSING")
check_condition "kernel.bin replaced with v2 content" "$([ "$kernel_content" = "kernel bytes for 2.0.0.0" ] && echo true || echo false)"

version_content=$(cat "$VERSION_FILE" 2>/dev/null || echo "MISSING")
check_condition "version file updated to 2.0.0.0" "$([ "$version_content" = "2.0.0.0" ] && echo true || echo false)"

echo
echo "=== downgrade blocked (no override) ==="

code=$(run_consumer "$FIXTURES_DIR/valid_v1.bin")
check_exit_code "older version v1 after v2 installed, no secret -> exit 6" 6 "$code"

version_content=$(cat "$VERSION_FILE" 2>/dev/null || echo "MISSING")
check_condition "version file unchanged after blocked downgrade" "$([ "$version_content" = "2.0.0.0" ] && echo true || echo false)"

echo
echo "=== downgrade allowed (correct override secret) ==="

DOWNGRADE_SECRET="integration-test-secret"
"$WORK_DIR/venv/bin/python" -c "
import hashlib, sys
sys.stdout.buffer.write(hashlib.sha256(b'$DOWNGRADE_SECRET').digest())
" > /etc/fota-secure/downgrade_secret.hash

code=$(run_consumer "$FIXTURES_DIR/valid_v1.bin" "$DOWNGRADE_SECRET")
check_exit_code "older version v1 with correct override secret -> exit 0" 0 "$code"

version_content=$(cat "$VERSION_FILE" 2>/dev/null || echo "MISSING")
check_condition "version file rolled back to 1.0.0.0" "$([ "$version_content" = "1.0.0.0" ] && echo true || echo false)"

echo
echo "=== downgrade with wrong override secret ==="

code=$(run_consumer "$FIXTURES_DIR/valid_v2.bin")
check_exit_code "re-upgrade to v2 to set up next check -> exit 0" 0 "$code"

code=$(run_consumer "$FIXTURES_DIR/valid_v1.bin" "definitely-the-wrong-secret")
check_exit_code "downgrade attempt with wrong secret -> exit 6" 6 "$code"

echo
echo "=== insufficient disk space ==="

# The consumer's disk-space pre-check (statvfs on the fixed install
# path in config.h) is otherwise never exercised - a real filesystem is
# never actually short of a few hundred KB. Mount a deliberately tiny
# tmpfs directly onto the install path so the check has something to
# fail against. large_payload.bin's 2 MiB incompressible payload
# guarantees the check trips regardless of tmpfs block-size rounding.
# fw_version 3.0.0.0 is higher than anything installed so far, so this
# reaches the disk-space check rather than being blocked as a downgrade.
mount -t tmpfs -o size=64k tmpfs "$INSTALL_DIR"

code=$(run_consumer "$FIXTURES_DIR/large_payload.bin")
check_exit_code "2 MiB payload, 64 KiB tmpfs install target -> exit 7 (insufficient disk space)" 7 "$code"

umount "$INSTALL_DIR"

echo
echo "================================"
echo "$pass_count passed, $fail_count failed"
if [ "$fail_count" -ne 0 ]; then
    exit 1
fi
