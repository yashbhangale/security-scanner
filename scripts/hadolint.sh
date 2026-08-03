#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "       HADOLINT DOCKERFILE SCAN"
echo "========================================="

REPORT_DIR="reports/hadolint"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Hadolint
# -------------------------------------------------

if ! command -v hadolint >/dev/null 2>&1; then
    echo "[ERROR] Hadolint is not installed."
    exit 1
fi

echo "[INFO] Hadolint Version"
hadolint --version
echo ""

# -------------------------------------------------
# Find Dockerfiles
# -------------------------------------------------

DOCKERFILES=$(find . -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.dockerfile" | grep -v ".git" || true)

if [[ -z "$DOCKERFILES" ]]; then
    echo "[INFO] No Dockerfiles found. Skipping."
    echo '{"files_scanned": 0, "results": []}' > "$REPORT_DIR/hadolint.json"
    exit 0
fi

echo "[INFO] Found Dockerfiles:"
echo "$DOCKERFILES" | while read -r f; do echo "  - $f"; done
echo ""

# -------------------------------------------------
# Run Hadolint on each Dockerfile
# -------------------------------------------------

ALL_RESULTS="[]"

echo "[INFO] Scanning Dockerfiles..."

while IFS= read -r dockerfile; do
    echo "  Scanning: $dockerfile"

    # Run hadolint and capture JSON output
    RESULT=$(hadolint --format json "$dockerfile" 2>/dev/null || true)

    if [[ -n "$RESULT" && "$RESULT" != "[]" ]]; then
        # Merge results
        ALL_RESULTS=$(python3 -c "
import json, sys
existing = json.loads('$ALL_RESULTS') if '$ALL_RESULTS' != '[]' else []
try:
    new = json.loads('''$RESULT''')
    if isinstance(new, list):
        existing.extend(new)
except:
    pass
print(json.dumps(existing))
" 2>/dev/null || echo "$ALL_RESULTS")
    fi
done <<< "$DOCKERFILES"

# Write consolidated report
echo "$ALL_RESULTS" | python3 -m json.tool > "$REPORT_DIR/hadolint.json" 2>/dev/null || echo "$ALL_RESULTS" > "$REPORT_DIR/hadolint.json"

echo ""
echo "[OK] Hadolint scan complete"

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

python3 -c "
import json
try:
    with open('$REPORT_DIR/hadolint.json') as f:
        data = json.load(f)
    if isinstance(data, list):
        total = len(data)
        severities = {}
        for item in data:
            level = item.get('level', 'unknown')
            severities[level] = severities.get(level, 0) + 1
        print(f'  Total Issues: {total}')
        for level, count in sorted(severities.items()):
            print(f'    {level:10s} : {count}')
    else:
        print('  No issues found')
except Exception as e:
    print(f'  Could not parse results: {e}')
" 2>/dev/null || echo "  (Could not parse results)"

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  JSON : $REPORT_DIR/hadolint.json"

echo ""
echo "========================================="
echo "  HADOLINT SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0
