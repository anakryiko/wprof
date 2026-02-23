#!/bin/bash
# Test script for --json/-j mode
# Captures a short trace and compares Perfetto vs JSON output
set -euo pipefail

WPROF=${WPROF:-./wprof}
DATA=$(mktemp /tmp/wprof-test-XXXXXX.data)
PB_TRACE=$(mktemp /tmp/wprof-test-XXXXXX.pb)
JSON_TRACE=$(mktemp /tmp/wprof-test-XXXXXX.json)
JSON_FILTERED=$(mktemp /tmp/wprof-test-XXXXXX-filtered.json)
PASS=0
FAIL=0

cleanup() {
	rm -f "$DATA" "$PB_TRACE" "$JSON_TRACE" "$JSON_FILTERED"
}
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

check() {
	if eval "$2"; then
		pass "$1"
	else
		fail "$1"
	fi
}

echo "=== JSON output mode tests ==="

# --- Test 1: validation ---
echo
echo "--- Validation tests ---"

check "-j without -T is rejected" \
	"! $WPROF -R -j 2>&1 | grep -q 'requires -T'"

# --- Test 2: capture data with timer stack traces ---
echo
echo "--- Capturing test data (200ms with timers) ---"
if ! sudo "$WPROF" -d200 -Stimer -D "$DATA" 2>&1; then
	echo "FATAL: Failed to capture test data (need sudo)"
	exit 1
fi

# --- Test 3: generate both formats ---
echo
echo "--- Generating Perfetto and JSON traces ---"
"$WPROF" -R -D "$DATA" -T "$PB_TRACE" 2>&1
"$WPROF" -R -D "$DATA" -j -T "$JSON_TRACE" 2>&1

check "Perfetto trace is non-empty" \
	"[ -s '$PB_TRACE' ]"
check "JSON trace is non-empty" \
	"[ -s '$JSON_TRACE' ]"

# --- Test 4: JSON format validation ---
echo
echo "--- JSON format validation ---"

JSON_LINES=$(wc -l < "$JSON_TRACE")
check "JSON has events (got $JSON_LINES lines)" \
	"[ '$JSON_LINES' -gt 0 ]"

# All event types and the fields they must have
VALID_TYPES="timer switch fork exec task_rename task_exit task_free hardirq softirq wq ipi_send ipi req_event req_task_event scx_dsq cuda_kernel cuda_memcpy cuda_memset cuda_sync cuda_api"

# validate every line is valid JSON with expected base fields
INVALID=$(python3 -c "
import json, sys
valid_types = set('$VALID_TYPES'.split())
common_fields = {'t', 'ts', 'cpu', 'numa'}
bad = 0
with open('$JSON_TRACE') as f:
    for i, line in enumerate(f, 1):
        try:
            obj = json.loads(line)
            for k in common_fields:
                assert k in obj, f'missing {k}'
            assert obj['t'] in valid_types, f'unknown t={obj[\"t\"]}'
            assert isinstance(obj['ts'], int), 'ts not int'
            assert isinstance(obj['cpu'], int), 'cpu not int'
            t = obj['t']
            if t == 'switch':
                for k in ('prev_tid', 'prev_pid', 'prev_comm', 'next_tid', 'next_pid', 'next_comm'):
                    assert k in obj, f'missing {k} for switch event'
            elif t == 'task_rename':
                for k in ('tid', 'pid', 'old_comm', 'new_comm'):
                    assert k in obj, f'missing {k} for task_rename event'
            elif t == 'fork':
                for k in ('tid', 'pid', 'comm', 'child_tid', 'child_pid', 'child_comm'):
                    assert k in obj, f'missing {k} for fork event'
            else:
                for k in ('tid', 'pid', 'comm'):
                    assert k in obj, f'missing {k} for {t} event'
        except Exception as e:
            print(f'Line {i}: {e}', file=sys.stderr)
            bad += 1
print(bad)
" 2>&1)

check "All JSON lines are valid (invalid: $INVALID)" \
	"[ '$INVALID' -eq 0 ]"

# check timestamps are monotonically non-decreasing
MONO=$(python3 -c "
import json
prev = -1
bad = 0
with open('$JSON_TRACE') as f:
    for line in f:
        ts = json.loads(line)['ts']
        if ts < prev:
            bad += 1
        prev = ts
print(bad)
" 2>&1)

check "Timestamps are monotonically non-decreasing (violations: $MONO)" \
	"[ '$MONO' -eq 0 ]"

# check stack_id is present on some timer events (since we captured with -Stimer)
HAS_STACK=$(python3 -c "
import json
cnt = 0
with open('$JSON_TRACE') as f:
    for line in f:
        obj = json.loads(line)
        if obj['t'] == 'timer' and 'stack_id' in obj:
            cnt += 1
print(cnt)
" 2>&1)

check "Some timer events have stack_id (got $HAS_STACK)" \
	"[ '$HAS_STACK' -gt 0 ]"

# check we have multiple event types
TYPE_CNT=$(python3 -c "
import json
types = set()
with open('$JSON_TRACE') as f:
    for line in f:
        types.add(json.loads(line)['t'])
print(len(types))
" 2>&1)

check "Multiple event types present (got $TYPE_CNT types)" \
	"[ '$TYPE_CNT' -gt 1 ]"

# --- Test 5: filtered output ---
echo
echo "--- Filter tests ---"
"$WPROF" -R -D "$DATA" -j -T "$JSON_FILTERED" --no-idle 2>&1

FILTERED_LINES=$(wc -l < "$JSON_FILTERED")
check "Filtered JSON has fewer events ($FILTERED_LINES < $JSON_LINES)" \
	"[ '$FILTERED_LINES' -lt '$JSON_LINES' ]"

# verify no idle tasks in filtered output
# For switch events: both prev and next must be non-idle (pid != 0) for at least one side
# For other events: pid must be non-zero
IDLE_IN_FILTERED=$(python3 -c "
import json
cnt = 0
with open('$JSON_FILTERED') as f:
    for line in f:
        obj = json.loads(line)
        if obj['t'] == 'switch':
            if obj['prev_pid'] == 0 and obj['next_pid'] == 0:
                cnt += 1
        else:
            if obj.get('pid', -1) == 0:
                cnt += 1
print(cnt)
" 2>&1)

check "No idle tasks in filtered output (found: $IDLE_IN_FILTERED)" \
	"[ '$IDLE_IN_FILTERED' -eq 0 ]"

# --- Test 6: compare event counts ---
echo
echo "--- Cross-format comparison ---"

# count JSON events by type
JSON_TYPE_COUNTS=$(python3 -c "
import json
from collections import Counter
counts = Counter()
with open('$JSON_TRACE') as f:
    for line in f:
        counts[json.loads(line)['t']] += 1
for t, c in sorted(counts.items()):
    print(f'{t} {c}')
" 2>&1)

echo "  JSON event counts:"
echo "$JSON_TYPE_COUNTS" | while read t c; do echo "    $t: $c"; done

# Get event counts from replay info and sum up expected JSON events
# waking/wakeup_new don't produce JSON events, cuda_call is merged into cuda_api
EXPECTED_TOTAL=$(python3 -c "
import re, subprocess, sys
out = subprocess.check_output(['$WPROF', '-RI', '-D', '$DATA'], stderr=subprocess.STDOUT, text=True)
total = 0
skip = {'waking', 'wakeup_new', 'cuda_call'}
for line in out.splitlines():
    m = re.match(r'\s+(\w+)\s+[\d.]+MB\s+\((\d+) records\)', line)
    if m and m.group(1) not in skip:
        total += int(m.group(2))
print(total)
" 2>&1)

check "Total JSON events match replay info ($JSON_LINES vs $EXPECTED_TOTAL)" \
	"[ '$JSON_LINES' -eq '$EXPECTED_TOTAL' ]"

# --- Summary ---
echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
