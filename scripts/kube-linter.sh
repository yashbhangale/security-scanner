#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "     KUBE-LINTER KUBERNETES SCAN"
echo "========================================="

REPORT_DIR="reports/kube-linter"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Check kube-linter
# -------------------------------------------------

if ! command -v kube-linter >/dev/null 2>&1; then
    echo "[ERROR] kube-linter is not installed."
    exit 1
fi

echo "[INFO] kube-linter Version"
kube-linter version
echo ""

# -------------------------------------------------
# Find Kubernetes Manifests
# -------------------------------------------------

# Look for directories containing k8s manifests
K8S_DIRS=()

# Check common directories
for dir in . k8s kubernetes manifests deploy deployments helm charts; do
    if [[ -d "$dir" ]]; then
        # Check if directory has yaml files with k8s resources
        if find "$dir" \( -name "*.yaml" -o -name "*.yml" \) -exec grep -l "^kind:" {} \; 2>/dev/null | grep -q .; then
            K8S_DIRS+=("$dir")
        fi
    fi
done

if [[ ${#K8S_DIRS[@]} -eq 0 ]]; then
    echo "[INFO] No Kubernetes manifests found. Skipping."
    echo '{"paths_scanned": [], "results": []}' > "$REPORT_DIR/kube-linter.json"
    exit 0
fi

echo "[INFO] Scanning directories:"
for d in "${K8S_DIRS[@]}"; do
    echo "  - $d"
done
echo ""

# -------------------------------------------------
# Run kube-linter
# -------------------------------------------------

echo "[INFO] Running kube-linter..."

# Scan each directory
SCAN_TARGETS="${K8S_DIRS[*]}"

kube-linter lint $SCAN_TARGETS \
    --format json \
    > "$REPORT_DIR/kube-linter.json" 2>/dev/null \
    || true

echo "[OK] kube-linter scan complete"

# -------------------------------------------------
# Generate Plain Text Report
# -------------------------------------------------

echo "[INFO] Generating text report..."

kube-linter lint $SCAN_TARGETS \
    --format plain \
    > "$REPORT_DIR/kube-linter.txt" 2>/dev/null \
    || true

echo "[OK] Text report generated"

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/kube-linter.json" ]]; then
    python3 -c "
import json
try:
    with open('$REPORT_DIR/kube-linter.json') as f:
        data = json.load(f)
    reports = data.get('Reports', [])
    checks = {}
    for r in reports:
        check = r.get('Check', 'unknown')
        checks[check] = checks.get(check, 0) + 1
    print(f'  Total Issues: {len(reports)}')
    print(f'  Unique Checks Failed: {len(checks)}')
    if checks:
        print('  Top Issues:')
        for check, count in sorted(checks.items(), key=lambda x: -x[1])[:5]:
            print(f'    {check}: {count}')
except Exception as e:
    print(f'  Could not parse results: {e}')
" 2>/dev/null || echo "  (Could not parse results)"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  JSON  : $REPORT_DIR/kube-linter.json"
echo "  Plain : $REPORT_DIR/kube-linter.txt"

echo ""
echo "========================================="
echo " KUBE-LINTER SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0
