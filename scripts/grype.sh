#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "      GRYPE DEPENDENCY SCAN"
echo "========================================="

REPORT_DIR="reports/grype"
SBOM_FILE="reports/syft/sbom-cyclonedx.json"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Grype
# -------------------------------------------------

if ! command -v grype >/dev/null 2>&1; then
    echo "[ERROR] Grype is not installed."
    exit 1
fi

echo "[INFO] Grype Version"
grype version
echo ""

# -------------------------------------------------
# Run Grype Scan
# -------------------------------------------------

# Prefer scanning SBOM if available (from Syft stage)
if [[ -f "$SBOM_FILE" ]]; then
    echo "[INFO] Scanning SBOM for vulnerabilities..."

    grype sbom:"$SBOM_FILE" \
        --output json \
        --file "$REPORT_DIR/grype.json" \
        || true

    echo "[OK] SBOM-based scan complete"
else
    echo "[INFO] No SBOM found. Scanning filesystem directly..."

    grype dir:. \
        --output json \
        --file "$REPORT_DIR/grype.json" \
        || true

    echo "[OK] Filesystem scan complete"
fi

# -------------------------------------------------
# Generate Table Report
# -------------------------------------------------

echo "[INFO] Generating table report..."

if [[ -f "$SBOM_FILE" ]]; then
    grype sbom:"$SBOM_FILE" \
        --output table \
        --file "$REPORT_DIR/grype.txt" \
        || true
else
    grype dir:. \
        --output table \
        --file "$REPORT_DIR/grype.txt" \
        || true
fi

echo "[OK] Table report generated"

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/grype.json" ]]; then
    python3 -c "
import json
try:
    with open('$REPORT_DIR/grype.json') as f:
        data = json.load(f)
    matches = data.get('matches', [])
    severities = {}
    for m in matches:
        sev = m.get('vulnerability', {}).get('severity', 'Unknown')
        severities[sev] = severities.get(sev, 0) + 1
    print(f'Total Vulnerabilities: {len(matches)}')
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Negligible']:
        if sev in severities:
            print(f'  {sev:12s} : {severities[sev]}')
except Exception as e:
    print(f'Could not parse results: {e}')
" 2>/dev/null || echo "  (Could not parse results)"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  JSON  : $REPORT_DIR/grype.json"
echo "  Table : $REPORT_DIR/grype.txt"

echo ""
echo "========================================="
echo "   GRYPE SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0
