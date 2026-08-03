#!/usr/bin/env bash

set -e

# =========================================
#         SECURITY SCANNER
#         PROJECT PROFILER
# =========================================
#
# Detects languages, package managers, frameworks,
# and infrastructure components in a target repository.
# Outputs both human-readable text and a JSON profile
# for consumption by the Jenkins pipeline.
#
# Usage: ./project-profiler.sh [target-directory]
# Output: reports/profile.json
# =========================================

TARGET_DIR="${1:-.}"
REPORT_DIR="reports"

mkdir -p "$REPORT_DIR"

cd "$TARGET_DIR"

echo "======================================="
echo "        SECURITY SCANNER"
echo "        PROJECT PROFILER"
echo "======================================="
echo ""
echo "Repository : $(basename "$(pwd)")"
echo "Path       : $(pwd)"
echo ""

# -------------------------------------------------
# Initialize JSON profile
# -------------------------------------------------

declare -a LANGUAGES=()
declare -a PACKAGE_MANAGERS=()
declare -a TECHNOLOGIES=()

# -------------------------------------------------
# Detect Languages (searches recursively)
# -------------------------------------------------

echo "========== Languages =========="

if find . -name "package.json" -not -path "./.git/*" -not -path "*/node_modules/*" | grep -q .; then
    echo "  Node.js"
    LANGUAGES+=("nodejs")
fi

if find . -name "pom.xml" -not -path "./.git/*" | grep -q .; then
    echo "  Java (Maven)"
    LANGUAGES+=("java")
fi

if find . \( -name "build.gradle" -o -name "build.gradle.kts" \) -not -path "./.git/*" | grep -q .; then
    if [[ ! " ${LANGUAGES[*]} " =~ " java " ]]; then
        echo "  Java (Gradle)"
        LANGUAGES+=("java")
    fi
fi

if find . \( -name "requirements.txt" -o -name "pyproject.toml" -o -name "setup.py" -o -name "Pipfile" \) -not -path "./.git/*" | grep -q .; then
    echo "  Python"
    LANGUAGES+=("python")
fi

if find . -name "go.mod" -not -path "./.git/*" | grep -q .; then
    echo "  Go"
    LANGUAGES+=("go")
fi

if find . -name "Cargo.toml" -not -path "./.git/*" | grep -q .; then
    echo "  Rust"
    LANGUAGES+=("rust")
fi

if find . -name "composer.json" -not -path "./.git/*" | grep -q .; then
    echo "  PHP"
    LANGUAGES+=("php")
fi

if find . -name "Gemfile" -not -path "./.git/*" | grep -q .; then
    echo "  Ruby"
    LANGUAGES+=("ruby")
fi

if find . -name "*.csproj" -not -path "./.git/*" | grep -q .; then
    echo "  .NET"
    LANGUAGES+=("dotnet")
fi

if [[ ${#LANGUAGES[@]} -eq 0 ]]; then
    echo "  (none detected)"
fi

echo ""

# -------------------------------------------------
# Detect Package Managers (searches recursively)
# -------------------------------------------------

echo "========== Package Managers =========="

if find . -name "package-lock.json" -not -path "./.git/*" -not -path "*/node_modules/*" | grep -q .; then
    echo "  npm"
    PACKAGE_MANAGERS+=("npm")
fi

if find . -name "pnpm-lock.yaml" -not -path "./.git/*" | grep -q .; then
    echo "  pnpm"
    PACKAGE_MANAGERS+=("pnpm")
fi

if find . -name "yarn.lock" -not -path "./.git/*" | grep -q .; then
    echo "  yarn"
    PACKAGE_MANAGERS+=("yarn")
fi

if find . -name "pom.xml" -not -path "./.git/*" | grep -q .; then
    echo "  Maven"
    PACKAGE_MANAGERS+=("maven")
fi

if find . \( -name "build.gradle" -o -name "build.gradle.kts" \) -not -path "./.git/*" | grep -q .; then
    echo "  Gradle"
    PACKAGE_MANAGERS+=("gradle")
fi

if find . \( -name "poetry.lock" -o -name "pyproject.toml" \) -not -path "./.git/*" | grep -q .; then
    echo "  Poetry"
    PACKAGE_MANAGERS+=("poetry")
fi

if find . -name "Pipfile.lock" -not -path "./.git/*" | grep -q .; then
    echo "  Pipenv"
    PACKAGE_MANAGERS+=("pipenv")
fi

if find . -name "requirements.txt" -not -path "./.git/*" | grep -q .; then
    echo "  pip"
    PACKAGE_MANAGERS+=("pip")
fi

if find . -name "Cargo.lock" -not -path "./.git/*" | grep -q .; then
    echo "  Cargo"
    PACKAGE_MANAGERS+=("cargo")
fi

if find . -name "go.sum" -not -path "./.git/*" | grep -q .; then
    echo "  Go Modules"
    PACKAGE_MANAGERS+=("gomod")
fi

if find . -name "composer.lock" -not -path "./.git/*" | grep -q .; then
    echo "  Composer"
    PACKAGE_MANAGERS+=("composer")
fi

if find . -name "Gemfile.lock" -not -path "./.git/*" | grep -q .; then
    echo "  Bundler"
    PACKAGE_MANAGERS+=("bundler")
fi

if [[ ${#PACKAGE_MANAGERS[@]} -eq 0 ]]; then
    echo "  (none detected)"
fi

echo ""

# -------------------------------------------------
# Detect Technologies / Infrastructure
# -------------------------------------------------

echo "========== Technologies =========="

if find . -name "Dockerfile" -not -path "./.git/*" | grep -q .; then
    echo "  Docker         : Yes"
    TECHNOLOGIES+=("docker")
fi

if find . -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -not -path "./.git/*" | grep -q .; then
    echo "  Docker Compose : Yes"
    TECHNOLOGIES+=("docker-compose")
fi

if find . -name "*.tf" -not -path "./.git/*" | grep -q .; then
    echo "  Terraform      : Yes"
    TECHNOLOGIES+=("terraform")
fi

if find . -name "Chart.yaml" -not -path "./.git/*" | grep -q .; then
    echo "  Helm           : Yes"
    TECHNOLOGIES+=("helm")
fi

# Kubernetes manifests (YAML files with 'kind:' field)
if find . \( -name "*.yaml" -o -name "*.yml" \) -not -path "./.git/*" -exec grep -l "^kind:" {} \; 2>/dev/null | grep -q .; then
    echo "  Kubernetes     : Yes"
    TECHNOLOGIES+=("kubernetes")
fi

if [[ -d ".github/workflows" ]]; then
    echo "  GitHub Actions : Yes"
    TECHNOLOGIES+=("github-actions")
fi

if [[ -f "Jenkinsfile" ]]; then
    echo "  Jenkins        : Yes"
    TECHNOLOGIES+=("jenkins")
fi

if [[ -f ".gitlab-ci.yml" ]]; then
    echo "  GitLab CI      : Yes"
    TECHNOLOGIES+=("gitlab-ci")
fi

if find . -name "argocd-*.yaml" -o -name "application.yaml" -not -path "./.git/*" 2>/dev/null | xargs grep -l "argoproj.io" 2>/dev/null | grep -q .; then
    echo "  ArgoCD         : Yes"
    TECHNOLOGIES+=("argocd")
fi

if find . -name "kustomization.yaml" -o -name "kustomization.yml" -not -path "./.git/*" | grep -q .; then
    echo "  Kustomize      : Yes"
    TECHNOLOGIES+=("kustomize")
fi

echo ""

# -------------------------------------------------
# Repository Information
# -------------------------------------------------

echo "========== Repository Statistics =========="

FILE_COUNT=$(find . -type f -not -path "./.git/*" | wc -l | tr -d ' ')
DIR_COUNT=$(find . -type d -not -path "./.git/*" | wc -l | tr -d ' ')

echo "  Files          : $FILE_COUNT"
echo "  Directories    : $DIR_COUNT"

echo ""
echo "========== Git Information =========="

GIT_BRANCH="unknown"
GIT_COMMIT="unknown"
GIT_REMOTE="unknown"

if git rev-parse --git-dir >/dev/null 2>&1; then
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    GIT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
    GIT_REMOTE=$(git remote get-url origin 2>/dev/null || echo "unknown")
fi

echo "  Branch         : $GIT_BRANCH"
echo "  Commit         : $GIT_COMMIT"
echo "  Remote         : $GIT_REMOTE"

echo ""

# -------------------------------------------------
# Generate JSON Profile
# -------------------------------------------------

json_array() {
    local arr=("$@")
    local result="["
    local first=true
    for item in "${arr[@]}"; do
        if [[ "$first" == "true" ]]; then
            result+="\"$item\""
            first=false
        else
            result+=",\"$item\""
        fi
    done
    result+="]"
    echo "$result"
}

LANG_JSON=$(json_array "${LANGUAGES[@]}")
PKG_JSON=$(json_array "${PACKAGE_MANAGERS[@]}")
TECH_JSON=$(json_array "${TECHNOLOGIES[@]}")

# Determine which scanners should run based on profile
SCANNERS=("trivy" "gitleaks" "semgrep")

# Always suggest sonar for code quality
SCANNERS+=("sonar")

# Always generate SBOM
SCANNERS+=("syft" "grype")

# IaC scanners
for tech in "${TECHNOLOGIES[@]}"; do
    case "$tech" in
        terraform|kubernetes|docker|github-actions)
            if [[ ! " ${SCANNERS[*]} " =~ " checkov " ]]; then
                SCANNERS+=("checkov")
            fi
            ;;
    esac
done

# Docker-specific
for tech in "${TECHNOLOGIES[@]}"; do
    if [[ "$tech" == "docker" ]]; then
        if [[ ! " ${SCANNERS[*]} " =~ " hadolint " ]]; then
            SCANNERS+=("hadolint")
        fi
        break
    fi
done

# Kubernetes-specific
for tech in "${TECHNOLOGIES[@]}"; do
    if [[ "$tech" == "kubernetes" || "$tech" == "helm" || "$tech" == "kustomize" ]]; then
        if [[ ! " ${SCANNERS[*]} " =~ " kube-linter " ]]; then
            SCANNERS+=("kube-linter")
        fi
        break
    fi
done

SCANNERS_JSON=$(json_array "${SCANNERS[@]}")

cat > "$REPORT_DIR/profile.json" <<EOF
{
  "repository": "$(basename "$(pwd)")",
  "path": "$(pwd)",
  "git": {
    "branch": "$GIT_BRANCH",
    "commit": "$GIT_COMMIT",
    "remote": "$GIT_REMOTE"
  },
  "languages": $LANG_JSON,
  "package_managers": $PKG_JSON,
  "technologies": $TECH_JSON,
  "scanners": $SCANNERS_JSON,
  "statistics": {
    "files": $FILE_COUNT,
    "directories": $DIR_COUNT
  }
}
EOF

echo "========== Recommended Scanners =========="
for s in "${SCANNERS[@]}"; do
    echo "  - $s"
done

echo ""
echo "========== Profile Saved =========="
echo "  Output: $REPORT_DIR/profile.json"
echo ""
echo "======================================="
echo "     PROFILING COMPLETED SUCCESSFULLY"
echo "======================================="

exit 0
