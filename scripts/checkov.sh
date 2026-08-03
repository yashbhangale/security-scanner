#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "        CHECKOV IaC SCAN"
echo "========================================="

REPORT_DIR="reports/checkov"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Checkov
# -------------------------------------------------

if ! command -v checkov >/dev/null 2>&1; then
    echo "[ERROR] Checkov is not installed."
    exit 1
fi

echo "[INFO] Checkov Version"
checkov --version
echo ""

# -------------------------------------------------
# Run Checkov Scan
# -------------------------------------------------

echo "[INFO] Scanning for Infrastructure as Code issues..."

# Scan all supported frameworks
checkov \
    --directory . \
    --output json \
    --output-file-path "$REPORT_DIR" \
    --soft-fail \
    --quiet \
    || true

# Rename output (checkov creates results_json.json)
if [[ -f "$REPORT_DIR/results_json.json" ]]; then
    mv "$REPORT_DIR/results_json.json" "$REPORT_DIR/checkov.json"
fi

echo "[OK] Checkov scan complete"

# -------------------------------------------------
# Generate SARIF Report
# -------------------------------------------------

echo "[INFO] Generating SARIF report..."

checkov \
    --directory . \
    --output sarif \
    --output-file-path "$REPORT_DIR" \
    --soft-fail \
    --quiet \
    || true

if [[ -f "$REPORT_DIR/results_sarif.sarif" ]]; then
    mv "$REPORT_DIR/results_sarif.sarif" "$REPORT_DIR/checkov.sarif"
fi

echo "[OK] SARIF report generated"

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/checkov.json" ]]; then
    python3 -c "
import json
try:
    with open('$REPORT_DIR/checkov.json') as f:
        data = json.load(f)
    # Checkov may return a list of check results
    if isinstance(data, list):
        total_passed = sum(r.get('summary', {}).get('passed', 0) for r in data)
        total_failed = sum(r.get('summary', {}).get('failed', 0) for r in data)
        total_skipped = sum(r.get('summary', {}).get('skipped', 0) for r in data)
    else:
        total_passed = data.get('summary', {}).get('passed', 0)
        total_failed = data.get('summary', {}).get('failed', 0)
        total_skipped = data.get('summary', {}).get('skipped', 0)
    print(f'  Passed  : {total_passed}')
    print(f'  Failed  : {total_failed}')
    print(f'  Skipped : {total_skipped}')
except Exception as e:
    print(f'  Could not parse results: {e}')
" 2>/dev/null || echo "  (Could not parse results)"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  JSON  : $REPORT_DIR/checkov.json"
echo "  SARIF : $REPORT_DIR/checkov.sarif"

echo ""
echo "========================================="
echo "  CHECKOV SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0
