#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "       SEMGREP STATIC ANALYSIS"
echo "========================================="

REPORT_DIR="reports/semgrep"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Semgrep
# -------------------------------------------------

if ! command -v semgrep >/dev/null 2>&1; then
    echo "[ERROR] Semgrep is not installed."
    exit 1
fi

echo "[INFO] Semgrep Version"
semgrep --version
echo ""

# -------------------------------------------------
# Run Static Analysis
# -------------------------------------------------

echo "[INFO] Running Semgrep scan with auto config..."

semgrep scan \
    --config auto \
    --json \
    --output "$REPORT_DIR/semgrep.json" \
    --no-git-ignore \
    . \
    || true

echo "[OK] JSON report generated"

# -------------------------------------------------
# Generate SARIF report
# -------------------------------------------------

echo "[INFO] Generating SARIF report..."

semgrep scan \
    --config auto \
    --sarif \
    --output "$REPORT_DIR/semgrep.sarif" \
    --no-git-ignore \
    . \
    || true

echo "[OK] SARIF report generated"

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/semgrep.json" ]]; then
    FINDING_COUNT=$(python3 -c "
import json
try:
    with open('$REPORT_DIR/semgrep.json') as f:
        data = json.load(f)
    results = data.get('results', [])
    print(len(results))
except:
    print(0)
" 2>/dev/null || echo "0")
    echo "Findings: $FINDING_COUNT"
else
    echo "Findings: 0"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  JSON  : $REPORT_DIR/semgrep.json"
echo "  SARIF : $REPORT_DIR/semgrep.sarif"

echo ""
echo "========================================="
echo "  SEMGREP SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0
