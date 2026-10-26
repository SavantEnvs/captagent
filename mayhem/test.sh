#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for captagent's packet decoder and SIP parser.
#
# Runs /mayhem/kat (built by mayhem/build.sh with normal flags, dynamically linked) and compares every
# line it prints with mayhem/kat.expected: addresses, ports, header and payload lengths that
# callback_proto() hands to the capture plan for a hand-built Ethernet/IPv4/UDP SIP frame (plain and
# 802.1Q-tagged), and the method, response code, Call-ID, CSeq, From/To users that parse_message()
# extracts from an INVITE and a 200 OK. A neutered or no-op build prints nothing and fails every line.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

KAT=/mayhem/kat
EXPECTED=mayhem/kat.expected
if [ ! -x "$KAT" ]; then echo "missing $KAT (mayhem/build.sh builds it)" >&2; emit_ctrf captagent-kat 0 1; exit 1; fi
if [ ! -f "$EXPECTED" ]; then echo "missing $EXPECTED" >&2; emit_ctrf captagent-kat 0 1; exit 1; fi

mapfile -t want < "$EXPECTED"
mapfile -t got < <("$KAT" 2>&1)

passed=0; failed=0
for i in "${!want[@]}"; do
  if [ "${got[$i]-}" = "${want[$i]}" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL line $((i + 1)): expected '${want[$i]}', got '${got[$i]-<none>}'" >&2
  fi
done
if [ "${#got[@]}" -ne "${#want[@]}" ]; then
  failed=$((failed + 1))
  echo "FAIL: kat printed ${#got[@]} lines, expected ${#want[@]}" >&2
fi
emit_ctrf captagent-kat "$passed" "$failed"
