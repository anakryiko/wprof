#!/bin/bash
# Test script for pytrace tracing.
# Run with: sudo bash test_pytrace.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WPROF="$SCRIPT_DIR/../src/wprof"
TEST_PY="$SCRIPT_DIR/test_pytrace.py"
DATA_OUT="/tmp/pytrace_test.data"
JSON_OUT="/tmp/pytrace_test.json"
PB_OUT="/tmp/pytrace_test.pb"

PYTHON=python3
if [ "$(uname -m)" = "aarch64" ]; then
    PLATFORM_PYTHON=/usr/local/fbcode/platform010-aarch64/bin/python3.12
else
    PLATFORM_PYTHON=/usr/local/fbcode/platform010/bin/python3.12
fi
for candidate in "$PLATFORM_PYTHON" python3; do
    if command -v "$candidate" &>/dev/null; then
        # Check if the binary has Python C API symbols in its symbol table
        if readelf -s "$(readlink -f "$(command -v "$candidate")")" 2>/dev/null | grep -q 'PyEval_SetProfile'; then
            PYTHON="$candidate"
            break
        fi
    fi
done
echo "Using Python: $PYTHON ($(readlink -f "$(command -v "$PYTHON")"))"

# Start the test Python program in background
"$PYTHON" "$TEST_PY" &
PYTRACE_PID=$!
echo "Started test Python process with PID: $PYTRACE_PID"
sleep 1

# Step 1: Capture raw data
echo ""
echo "=== Step 1: Capturing (2s)... ==="
"$WPROF" -f py-trace=$PYTRACE_PID -d2000 -vv --log=pytrace --log=tracee --log=inject -D "$DATA_OUT" 2>&1

kill $PYTRACE_PID 2>/dev/null || true
wait $PYTRACE_PID 2>/dev/null || true

# Step 2: Generate JSON from captured data
echo ""
echo "=== Step 2: Generating JSON trace... ==="
"$WPROF" -R -J "$JSON_OUT" -D "$DATA_OUT" 2>&1

# Step 3: Generate Perfetto trace from same data
echo ""
echo "=== Step 3: Generating Perfetto trace... ==="
"$WPROF" -R -T "$PB_OUT" -D "$DATA_OUT" 2>&1

# Analyze JSON output
echo ""
echo "=== JSON header ==="
head -1 "$JSON_OUT" | python3 -m json.tool

echo ""
echo "=== pytrace event counts ==="
grep -c '"t":"pytrace_entry"' "$JSON_OUT" || echo "pytrace_entry: 0"
grep -c '"t":"pytrace_exit"' "$JSON_OUT" || echo "pytrace_exit: 0"

echo ""
echo "=== sample pytrace_entry events ==="
grep '"t":"pytrace_entry"' "$JSON_OUT" | head -5 | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(f\"  ts={e['ts']:.9f} name={e.get('name','?')} file={e.get('file','?')} lineno={e.get('lineno','?')}\")
"

echo ""
echo "=== sample pytrace_exit events ==="
grep '"t":"pytrace_exit"' "$JSON_OUT" | head -5 | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(f\"  ts={e['ts']:.9f} name={e.get('name','?')}\")
"

echo ""
echo "=== all unique pytrace function names ==="
grep '"t":"pytrace_entry"' "$JSON_OUT" | python3 -c "
import sys, json, collections
names = collections.Counter()
for line in sys.stdin:
    e = json.loads(line)
    names[e.get('name','?')] += 1
for name, cnt in names.most_common():
    print(f'  {cnt:6d}  {name}')
"

echo ""
echo "=== pytrace events per tid ==="
grep '"t":"pytrace_entry"' "$JSON_OUT" | python3 -c "
import sys, json, collections
tids = collections.Counter()
for line in sys.stdin:
    e = json.loads(line)
    tids[e.get('task', {}).get('tid', '?')] += 1
for tid, cnt in sorted(tids.items()):
    print(f'  tid={tid}: {cnt} calls')
"

echo ""
echo "Data file:     $DATA_OUT"
echo "JSON output:   $JSON_OUT"
echo "Perfetto trace: $PB_OUT"
echo "Done."
