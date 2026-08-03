# Security Scanner

A DevSecOps automation platform that scans any Git repository using a single generic Jenkins pipeline. Users provide a repository URL, and the platform automatically profiles the project, selects relevant scanners, executes them, aggregates results, and generates a comprehensive security report.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Pipeline Parameters](#pipeline-parameters)
- [Scanner Modules](#scanner-modules)
- [Project Profiler](#project-profiler)
- [Reports](#reports)
- [Running Scanners Locally](#running-scanners-locally)
- [Troubleshooting](#troubleshooting)
- [Development Roadmap](#development-roadmap)
- [License](#license)

---

## Overview

Security Scanner eliminates the need to configure security tools for every project. It provides a single reusable pipeline that:

1. Clones the target repository
2. Automatically detects the project type, languages, and infrastructure
3. Selects and runs only the relevant security scanners
4. Aggregates all findings into a unified report
5. Delivers results via Jenkins UI, HTML dashboard, or email

---

## Features

- Automatic project profiling (languages, frameworks, infrastructure detection)
- Conditional scanner execution based on project profile
- Support for 9 security scanning tools
- Consolidated HTML dashboard with security scoring
- Full standalone report with CSS/JS for offline viewing
- JSON and SARIF output formats
- SBOM generation (CycloneDX and SPDX)
- Email notification support
- Docker-based deployment (Jenkins + SonarQube)
- Configurable scan levels (basic and full)

---

## Architecture

```
                         User
                           |
                    Repository URL
                           |
                           v
                    Jenkins Pipeline
                           |
                           v
                Clone Target Repository
                           |
                           v
                  Project Profiler
                           |
      +--------------------+--------------------+
      |                    |                    |
      v                    v                    v
 Detect Language     Detect Frameworks   Detect Infrastructure
      |                    |                    |
      +--------------------+--------------------+
                           |
                           v
                   Scanner Engine
      +--------------------------------------------+
      | Trivy       | Gitleaks    | Semgrep        |
      | SonarQube   | Syft        | Grype          |
      | Checkov     | Hadolint    | kube-linter    |
      +--------------------------------------------+
                           |
                           v
                   Result Aggregator
                           |
                           v
              HTML / JSON / SARIF / SBOM
                           |
                           v
               Jenkins / Email / Slack
```

---

## Project Structure

```
security-scanner/
|
|-- Jenkinsfile                  # Pipeline definition
|-- dockerfile                   # Jenkins image with all tools
|-- readme.md                    # This file
|-- usage.md                     # Step-by-step usage guide
|-- buildinfo.md                 # Project documentation and roadmap
|-- LICENSE
|-- .gitignore
|
|-- scripts/
|   |-- project-profiler.sh     # Language and tech detection
|   |-- trivy.sh                # Vulnerability and misconfiguration scan
|   |-- gitleaks.sh             # Secret detection
|   |-- semgrep.sh              # Static code analysis
|   |-- sonar.sh                # SonarQube code quality
|   |-- syft.sh                 # SBOM generation
|   |-- grype.sh                # Dependency vulnerability scan
|   |-- checkov.sh              # Infrastructure as Code scan
|   |-- hadolint.sh             # Dockerfile linting
|   |-- kube-linter.sh          # Kubernetes manifest validation
|   |-- report.py               # Report aggregator and HTML generator
|
|-- templates/
|   |-- report.html             # HTML report template (inline styles)
|
|-- docker/
|   |-- docker-compose.yml      # Jenkins + DinD + SonarQube stack
|
|-- reports/                    # Generated reports (gitignored)
|-- docs/                       # Additional documentation
|-- sample-output/              # Example scan outputs
```

---

## Prerequisites

- Docker and Docker Compose
- Git
- At least 4 GB of available RAM (SonarQube requirement)

All security tools are pre-installed in the Docker image. No manual tool installation is required.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yashbhangale/security-scanner.git
cd security-scanner
```

### 2. Build and start the infrastructure

```bash
cd docker
docker compose up -d
```

This starts three containers:

| Container       | Port  | Purpose                     |
|-----------------|-------|-----------------------------|
| jenkins         | 8080  | CI/CD pipeline engine       |
| jenkins-docker  | --    | Docker-in-Docker for builds |
| sonarqube       | 9000  | Code quality analysis       |

### 3. Get the Jenkins initial password

```bash
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

### 4. Complete Jenkins setup

1. Open http://localhost:8080
2. Enter the initial admin password
3. Install suggested plugins
4. Create an admin user

### 5. Configure SonarQube (optional)

1. Open http://localhost:9000
2. Login with admin / admin
3. Change the password when prompted
4. Create a project and generate an authentication token

---

## Configuration

### Jenkins Pipeline Job

1. Navigate to Jenkins > New Item
2. Name: `security-scanner`
3. Type: Pipeline
4. Pipeline configuration:
   - Definition: Pipeline script from SCM
   - SCM: Git
   - Repository URL: `https://github.com/yashbhangale/security-scanner.git`
   - Branch: `main`
   - Script Path: `Jenkinsfile`
5. Save

### SonarQube Integration (optional)

1. In Jenkins, go to Manage Jenkins > Credentials
2. Add a Secret Text credential with your SonarQube token
3. Go to Manage Jenkins > System > SonarQube Servers
   - Name: sonarqube
   - URL: http://sonarqube:9000
   - Token: select the credential

### Environment Variables

| Variable         | Default                  | Description                  |
|------------------|--------------------------|------------------------------|
| SONAR_HOST_URL   | http://sonarqube:9000    | SonarQube server URL         |
| SONAR_AUTH_TOKEN | (none)                   | SonarQube authentication token |

---

## Usage

### Running a scan

1. In Jenkins, click Build with Parameters
2. Fill in the required parameters (see below)
3. Click Build
4. View results in the build sidebar under Security Scan Report
5. Download the full report from build artifacts

### Pipeline Parameters

| Parameter         | Required | Default | Description                                     |
|-------------------|----------|---------|--------------------------------------------------|
| REPO_URL          | Yes      | --      | Git repository URL to scan                       |
| BRANCH            | No       | main    | Branch to scan                                   |
| EMAIL             | No       | --      | Email address for report delivery                |
| SCAN_LEVEL        | No       | full    | basic (Trivy + Gitleaks) or full (all scanners)  |
| SONAR_PROJECT_KEY | No       | --      | SonarQube project key (empty to skip SonarQube)  |

### Scan Levels

**basic** runs only:
- Trivy (filesystem vulnerabilities, secrets, misconfigurations)
- Gitleaks (hardcoded secrets)

**full** runs all applicable scanners based on the project profile. Scanners that are not relevant to the target repository are automatically skipped.

---

## Scanner Modules

### Trivy

| Field   | Value                                          |
|---------|------------------------------------------------|
| Purpose | Vulnerabilities, secrets, misconfigurations    |
| Output  | JSON, table, CycloneDX SBOM                   |
| Script  | scripts/trivy.sh                               |
| Reports | reports/trivy/trivy-report.json, trivy-report.txt, sbom.json |

### Gitleaks

| Field   | Value                                |
|---------|--------------------------------------|
| Purpose | Hardcoded secret detection           |
| Output  | JSON                                 |
| Script  | scripts/gitleaks.sh                  |
| Reports | reports/gitleaks/gitleaks.json, gitleaks-history.json |

### Semgrep

| Field   | Value                          |
|---------|--------------------------------|
| Purpose | Static code analysis (SAST)    |
| Output  | JSON, SARIF                    |
| Script  | scripts/semgrep.sh             |
| Reports | reports/semgrep/semgrep.json, semgrep.sarif |

### SonarQube

| Field   | Value                                          |
|---------|------------------------------------------------|
| Purpose | Code quality, maintainability, security hotspots |
| Output  | JSON (via API)                                 |
| Script  | scripts/sonar.sh                               |
| Reports | reports/sonar/sonar-measures.json, sonar-issues.json, sonar-quality-gate.json |

### Syft

| Field   | Value                            |
|---------|----------------------------------|
| Purpose | Software Bill of Materials (SBOM)|
| Output  | CycloneDX JSON, SPDX JSON       |
| Script  | scripts/syft.sh                  |
| Reports | reports/syft/sbom-cyclonedx.json, sbom-spdx.json, sbom-syft.json |

### Grype

| Field   | Value                                          |
|---------|------------------------------------------------|
| Purpose | Dependency vulnerability scanning              |
| Output  | JSON, table                                    |
| Script  | scripts/grype.sh                               |
| Reports | reports/grype/grype.json, grype.txt            |
| Notes   | Uses SBOM from Syft if available               |

### Checkov

| Field      | Value                                       |
|------------|---------------------------------------------|
| Purpose    | Infrastructure as Code security             |
| Supports   | Terraform, Kubernetes, Docker, GitHub Actions |
| Output     | JSON, SARIF                                 |
| Script     | scripts/checkov.sh                          |
| Reports    | reports/checkov/checkov.json, checkov.sarif  |
| Conditions | Runs only when IaC files are detected       |

### Hadolint

| Field      | Value                                    |
|------------|------------------------------------------|
| Purpose    | Dockerfile best practices linting        |
| Output     | JSON                                     |
| Script     | scripts/hadolint.sh                      |
| Reports    | reports/hadolint/hadolint.json           |
| Conditions | Runs only when Dockerfiles are detected  |

### kube-linter

| Field      | Value                                         |
|------------|-----------------------------------------------|
| Purpose    | Kubernetes manifest validation                |
| Output     | JSON, plain text                              |
| Script     | scripts/kube-linter.sh                        |
| Reports    | reports/kube-linter/kube-linter.json, kube-linter.txt |
| Conditions | Runs only when Kubernetes manifests are detected |

---

## Project Profiler

The profiler (`scripts/project-profiler.sh`) automatically detects:

### Languages
Go, Java, Node.js, Python, Rust, PHP, Ruby, .NET

### Package Managers
npm, pnpm, Yarn, Maven, Gradle, Poetry, Pipenv, pip, Cargo, Go Modules, Composer, Bundler

### Technologies
Docker, Docker Compose, Kubernetes, Helm, Terraform, GitHub Actions, Jenkins, GitLab CI, ArgoCD, Kustomize

### Repository Information
Branch, commit hash, remote URL, file count, directory count

### Output
The profiler generates `reports/profile.json` containing all detected attributes and a list of recommended scanners. The pipeline reads this file to determine which scan stages to execute.

---

## Reports

### Generated Files

```
reports/
|-- profile.json              # Project profile
|-- summary.json              # Aggregated scan metrics
|-- report.html               # Inline-styled report (for Jenkins)
|-- report-full.html          # Standalone report (full CSS/JS)
|-- trivy/
|   |-- trivy-report.json
|   |-- trivy-report.txt
|   |-- sbom.json
|-- gitleaks/
|   |-- gitleaks.json
|   |-- gitleaks-history.json
|-- semgrep/
|   |-- semgrep.json
|   |-- semgrep.sarif
|-- sonar/
|   |-- sonar-measures.json
|   |-- sonar-issues.json
|   |-- sonar-quality-gate.json
|-- syft/
|   |-- sbom-cyclonedx.json
|   |-- sbom-spdx.json
|   |-- sbom-syft.json
|-- grype/
|   |-- grype.json
|   |-- grype.txt
|-- checkov/
|   |-- checkov.json
|   |-- checkov.sarif
|-- hadolint/
|   |-- hadolint.json
|-- kube-linter/
|   |-- kube-linter.json
|   |-- kube-linter.txt
```

### HTML Dashboard

The report includes:

- Security score (0-100) with color-coded indicator
- Severity breakdown (Critical, High, Medium, Low)
- Per-scanner result cards with pass/warn/fail status
- Top findings table sorted by severity
- Download links for all raw report files

### Security Score Calculation

| Finding Type             | Penalty                |
|--------------------------|------------------------|
| Critical vulnerability   | -10 each (max -40)     |
| High severity issue      | -5 each (max -30)      |
| Medium severity issue    | -2 each (max -20)      |
| Low severity issue       | -1 each (max -10)      |
| Docker/Kubernetes issues | -2 each (max -10)      |

---

## Running Scanners Locally

Individual scanners can be executed outside Jenkins:

```bash
# Navigate to the target repository
cd /path/to/target-repo

# Run the profiler
/path/to/security-scanner/scripts/project-profiler.sh .

# Run individual scanners
/path/to/security-scanner/scripts/trivy.sh
/path/to/security-scanner/scripts/gitleaks.sh
/path/to/security-scanner/scripts/semgrep.sh
/path/to/security-scanner/scripts/syft.sh
/path/to/security-scanner/scripts/grype.sh

# Generate the HTML report
python3 /path/to/security-scanner/scripts/report.py \
    --reports-dir reports \
    --template /path/to/security-scanner/templates/report.html \
    --output reports/report.html
```

Each scanner writes its output to `reports/<scanner-name>/` within the current directory.

---

## Troubleshooting

### Jenkins cannot connect to Docker

Ensure the Docker-in-Docker container is running:

```bash
docker ps | grep jenkins-docker
```

Verify the certificates volume is shared between containers.

### SonarQube fails to start

SonarQube requires elevated memory settings:

```bash
sudo sysctl -w vm.max_map_count=262144
```

To make this persistent, add `vm.max_map_count=262144` to `/etc/sysctl.conf`.

### Scanner not found errors

All tools are installed in the Docker image. If you see "not installed" errors:

1. Verify the image was rebuilt after the latest Dockerfile changes
2. Rebuild with: `cd docker && docker compose build --no-cache && docker compose up -d`

### Pipeline fails at a scanner stage

All scanners use `|| true` to prevent findings from failing the build. If a stage fails, the cause is typically a missing tool or a permissions issue, not scan findings. Check the console output for the specific error.

### Empty or unstyled HTML report

Jenkins HTML Publisher strips CSS and JavaScript for security. The inline-styled `report.html` provides a basic view. For the full styled version, download `report-full.html` from the build artifacts and open it in a browser.

### Profiler does not detect languages

The profiler searches recursively for language indicator files (package.json, go.mod, pom.xml, etc.). If the target repository uses an unusual structure, verify that these files exist somewhere in the repository tree.

### Groovy sandbox errors

If Jenkins reports a `RejectedAccessException`, the pipeline uses a method that requires script approval. The current Jenkinsfile avoids all sandbox-restricted methods. If you encounter this after modifications, go to Manage Jenkins > In-process Script Approval and approve the listed signature.

---

## Technology Stack

| Category            | Technology               |
|---------------------|--------------------------|
| CI/CD               | Jenkins                  |
| SCM                 | GitHub                   |
| Scripting           | Bash, Python             |
| Containerization    | Docker, Docker Compose   |
| Vulnerability Scan  | Trivy, Grype             |
| Secret Detection    | Gitleaks                 |
| Static Analysis     | Semgrep                  |
| Code Quality        | SonarQube                |
| SBOM Generation     | Syft                     |
| IaC Security        | Checkov                  |
| Dockerfile Linting  | Hadolint                 |
| Kubernetes Linting  | kube-linter              |
| Reporting           | HTML, JSON, SARIF        |

---

## Installed Tool Versions

The Docker image includes:

| Tool         | Installation Method                              |
|--------------|--------------------------------------------------|
| Trivy        | Official install script                          |
| Gitleaks     | GitHub release binary (v8.30.1)                  |
| Syft         | Official install script                          |
| Grype        | Official install script                          |
| Hadolint     | GitHub release binary                            |
| kube-linter  | GitHub release binary (v0.7.1)                   |
| Semgrep      | pip (Python venv)                                |
| Checkov      | pip (Python venv)                                |
| sonar-scanner| SonarSource distribution (v6.2.1)               |

---

## Stopping the Infrastructure

```bash
cd docker
docker compose down
```

To remove all data volumes (full reset):

```bash
docker compose down -v
```

---

## Development Roadmap

| Phase | Description                  | Status      |
|-------|------------------------------|-------------|
| 1     | Jenkins setup and pipeline   | Complete    |
| 2     | Project Profiler             | Complete    |
| 3     | Trivy scanner                | Complete    |
| 4     | Report parsing               | Complete    |
| 5     | Gitleaks scanner             | Complete    |
| 6     | Semgrep scanner              | Complete    |
| 7     | SonarQube scanner            | Complete    |
| 8     | Syft SBOM generator          | Complete    |
| 9     | Grype scanner                | Complete    |
| 10    | Checkov IaC scanner          | Complete    |
| 11    | Hadolint scanner             | Complete    |
| 12    | kube-linter scanner          | Complete    |
| 13    | HTML report generator        | Complete    |
| 14    | Email notifications          | Complete    |

---

## License

This project is open source. See the [LICENSE](LICENSE) file for details.
