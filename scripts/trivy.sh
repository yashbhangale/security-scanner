#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "         TRIVY SECURITY SCAN"
echo "========================================="

REPORT_DIR="reports/trivy"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Trivy
# -------------------------------------------------

if ! command -v trivy >/dev/null 2>&1; then
    echo "[ERROR] Trivy is not installed."
    exit 1
fi

echo "[INFO] Trivy Version"

trivy --version

echo ""

# -------------------------------------------------
# Filesystem Scan
# -------------------------------------------------

echo "[INFO] Running filesystem scan..."

trivy fs . \
    --scanners vuln,secret,misconfig \
    --format json \
    --output "$REPORT_DIR/trivy-report.json"

echo "[OK] JSON report generated"

# -------------------------------------------------
# Human Readable Report
# -------------------------------------------------

echo "[INFO] Generating table report..."

trivy fs . \
    --scanners vuln,secret,misconfig \
    --format table \
    --output "$REPORT_DIR/trivy-report.txt"

echo "[OK] Table report generated"

# -------------------------------------------------
# SBOM
# -------------------------------------------------

echo "[INFO] Generating CycloneDX SBOM..."

trivy fs . \
    --format cyclonedx \
    --output "$REPORT_DIR/sbom.json"

echo "[OK] SBOM generated"

# -------------------------------------------------
# Console Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"

echo "JSON  : $REPORT_DIR/trivy-report.json"
echo "TABLE : $REPORT_DIR/trivy-report.txt"
echo "SBOM  : $REPORT_DIR/sbom.json"

echo ""
echo "========================================="
echo "     TRIVY SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0
