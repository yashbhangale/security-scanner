#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "         GITLEAKS SECRET SCAN"
echo "========================================="

REPORT_DIR="reports/gitleaks"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Gitleaks
# -------------------------------------------------

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "[ERROR] Gitleaks is not installed."
    exit 1
fi

echo "[INFO] Gitleaks Version"
gitleaks version
echo ""

# -------------------------------------------------
# Run Secret Detection
# -------------------------------------------------

echo "[INFO] Scanning repository for secrets..."

# Run gitleaks on the directory (detect mode)
# Exit code 1 means leaks found - we don't want to fail the pipeline
gitleaks detect \
    --source . \
    --report-format json \
    --report-path "$REPORT_DIR/gitleaks.json" \
    --no-banner \
    || LEAKS_FOUND=$?

LEAKS_FOUND=${LEAKS_FOUND:-0}

# -------------------------------------------------
# Also scan git history
# -------------------------------------------------

echo "[INFO] Scanning git history for secrets..."

gitleaks detect \
    --source . \
    --report-format json \
    --report-path "$REPORT_DIR/gitleaks-history.json" \
    --log-opts="--all" \
    --no-banner \
    || true

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/gitleaks.json" ]]; then
    LEAK_COUNT=$(python3 -c "
import json
try:
    with open('$REPORT_DIR/gitleaks.json') as f:
        data = json.load(f)
    print(len(data) if isinstance(data, list) else 0)
except:
    print(0)
" 2>/dev/null || echo "0")
    echo "Secrets Found (current): $LEAK_COUNT"
else
    echo "Secrets Found (current): 0"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  Current Scan : $REPORT_DIR/gitleaks.json"
echo "  History Scan : $REPORT_DIR/gitleaks-history.json"

echo ""
echo "========================================="
echo "   GITLEAKS SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

# Exit 0 even if leaks found - pipeline handles severity
exit 0
