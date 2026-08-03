#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "         SYFT SBOM GENERATION"
echo "========================================="

REPORT_DIR="reports/syft"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check Syft
# -------------------------------------------------

if ! command -v syft >/dev/null 2>&1; then
    echo "[ERROR] Syft is not installed."
    exit 1
fi

echo "[INFO] Syft Version"
syft version
echo ""

# -------------------------------------------------
# Generate CycloneDX SBOM
# -------------------------------------------------

echo "[INFO] Generating CycloneDX SBOM..."

syft dir:. \
    --output cyclonedx-json="$REPORT_DIR/sbom-cyclonedx.json"

echo "[OK] CycloneDX SBOM generated"

# -------------------------------------------------
# Generate SPDX SBOM
# -------------------------------------------------

echo "[INFO] Generating SPDX SBOM..."

syft dir:. \
    --output spdx-json="$REPORT_DIR/sbom-spdx.json"

echo "[OK] SPDX SBOM generated"

# -------------------------------------------------
# Generate JSON Summary
# -------------------------------------------------

echo "[INFO] Generating JSON summary..."

syft dir:. \
    --output json="$REPORT_DIR/sbom-syft.json"

echo "[OK] JSON summary generated"

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/sbom-cyclonedx.json" ]]; then
    COMPONENT_COUNT=$(python3 -c "
import json
try:
    with open('$REPORT_DIR/sbom-cyclonedx.json') as f:
        data = json.load(f)
    components = data.get('components', [])
    print(len(components))
except:
    print(0)
" 2>/dev/null || echo "unknown")
    echo "Components Found: $COMPONENT_COUNT"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  CycloneDX : $REPORT_DIR/sbom-cyclonedx.json"
echo "  SPDX      : $REPORT_DIR/sbom-spdx.json"
echo "  Syft JSON : $REPORT_DIR/sbom-syft.json"

echo ""
echo "========================================="
echo "   SYFT SBOM GENERATION COMPLETED"
echo "========================================="

exit 0
