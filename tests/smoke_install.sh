#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "FAIL: $1"
  FAIL=$((FAIL + 1))
}

# Check opn --help exits 0
if opn --help > /dev/null 2>&1; then
  pass "opn --help exits 0"
else
  fail "opn --help exits 0"
fi

# Check opn port 0 --json produces valid JSON
output=$(opn port 0 --json 2>/dev/null) || true
if echo "$output" | python3 -m json.tool > /dev/null 2>&1; then
  pass "opn port 0 --json produces valid JSON"
else
  fail "opn port 0 --json produces valid JSON"
fi

# Check opn sockets --json produces valid JSON
output=$(opn sockets --json 2>/dev/null) || true
if echo "$output" | python3 -m json.tool > /dev/null 2>&1; then
  pass "opn sockets --json produces valid JSON"
else
  fail "opn sockets --json produces valid JSON"
fi

# Check opn file /dev/null exits without error (code 0 or 1)
rc=0
opn file /dev/null > /dev/null 2>&1 || rc=$?
if [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; then
  pass "opn file /dev/null exits with code $rc"
else
  fail "opn file /dev/null exits with unexpected code $rc"
fi

# Summary
echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi

exit 0
