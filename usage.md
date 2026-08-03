# Security Scanner - Usage Guide

## Prerequisites

- Docker & Docker Compose installed
- Git installed
- A target repository URL to scan

---

## 1. Start the Infrastructure

```bash
cd docker
docker compose up -d
```

This starts three containers:

| Container | Port | Purpose |
|-----------|------|---------|
| jenkins | 8080 | CI/CD Pipeline |
| jenkins-docker | - | Docker-in-Docker for builds |
| sonarqube | 9000 | Code quality analysis |

---

## 2. Initial Jenkins Setup

1. Open http://localhost:8080
2. Get the initial admin password:

```bash
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

3. Install suggested plugins
4. Create an admin user

---

## 3. Initial SonarQube Setup

1. Open http://localhost:9000
2. Login with `admin` / `admin`
3. Change password when prompted
4. Create a project and note the project key
5. Generate an authentication token under **My Account → Security → Tokens**

---

## 4. Configure Jenkins Credentials

1. Go to **Jenkins → Manage Jenkins → Credentials**
2. Add SonarQube token as a secret text credential
3. Go to **Manage Jenkins → System → SonarQube Servers**
   - Name: `sonarqube`
   - URL: `http://sonarqube:9000`
   - Token: select the credential you added

---

## 5. Create the Pipeline Job

1. Go to **Jenkins → New Item**
2. Name: `security-scanner`
3. Type: **Pipeline**
4. Under Pipeline configuration:
   - Definition: **Pipeline script from SCM**
   - SCM: **Git**
   - Repository URL: URL of this security-scanner repo
   - Branch: `main`
   - Script Path: `Jenkinsfile`
5. Save

---

## 6. Run a Scan

1. Click **Build with Parameters**
2. Fill in:

| Parameter | Example | Description |
|-----------|---------|-------------|
| REPO_URL | `https://github.com/user/project.git` | Target repo to scan |
| BRANCH | `main` | Branch to scan |
| EMAIL | `you@example.com` | (Optional) Email for report |
| SCAN_LEVEL | `full` | `basic` = Trivy + Gitleaks only, `full` = all scanners |
| SONAR_PROJECT_KEY | `my-project` | (Optional) Leave empty to skip SonarQube |

3. Click **Build**

---

## 7. View Results

After the pipeline completes:

- **HTML Report**: Click the build → **Security Scan Report** on the left sidebar
- **Archived Artifacts**: Click the build → **Artifacts** to download raw JSON/SARIF files
- **Console Output**: Shows live scan progress per stage

---

## 8. Understanding the Report

The HTML dashboard shows:

- **Security Score** (0-100): Weighted score based on all findings
- **Severity Grid**: Critical / High / Medium / Low counts
- **Scanner Cards**: Per-scanner summary with pass/warn/fail status
- **Top Findings**: Detailed table of most severe issues
- **Download Links**: Direct links to raw report files

### Score Calculation

| Finding Type | Penalty |
|-------------|---------|
| Critical vulnerability | -10 each (max -40) |
| High severity issue | -5 each (max -30) |
| Medium severity issue | -2 each (max -20) |
| Low severity issue | -1 each (max -10) |
| Docker/K8s issues | -2 each (max -10) |

---

## 9. Scan Levels

### Basic Scan
Runs only:
- **Trivy** — filesystem vulnerabilities, secrets, misconfigurations
- **Gitleaks** — hardcoded secrets

### Full Scan
Runs all scanners:
- Trivy, Gitleaks, Semgrep, SonarQube, Syft, Grype, Checkov, Hadolint, kube-linter

The profiler automatically skips scanners that aren't relevant (e.g., Hadolint is skipped if no Dockerfile exists).

---

## 10. Running Scripts Locally

You can run individual scanners outside Jenkins:

```bash
# Profile a project
cd /path/to/target-repo
/path/to/security-scanner/scripts/project-profiler.sh .

# Run Trivy
/path/to/security-scanner/scripts/trivy.sh

# Run Gitleaks
/path/to/security-scanner/scripts/gitleaks.sh

# Generate report from existing results
python3 /path/to/security-scanner/scripts/report.py \
    --reports-dir reports \
    --template /path/to/security-scanner/templates/report.html \
    --output reports/report.html
```

Each scanner writes output to `reports/<scanner-name>/`.

---

## 11. Required Tools (on Jenkins Agent)

These tools must be available on the Jenkins agent for full scan:

| Tool | Install |
|------|---------|
| trivy | https://aquasecurity.github.io/trivy |
| gitleaks | https://github.com/gitleaks/gitleaks |
| semgrep | `pip install semgrep` |
| sonar-scanner | https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/ |
| syft | https://github.com/anchore/syft |
| grype | https://github.com/anchore/grype |
| checkov | `pip install checkov` |
| hadolint | https://github.com/hadolint/hadolint |
| kube-linter | https://github.com/stackrox/kube-linter |
| python3 | Required for report generation |

---

## 12. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| SONAR_HOST_URL | `http://sonarqube:9000` | SonarQube server URL |
| SONAR_AUTH_TOKEN | (none) | SonarQube authentication token |

---

## 13. Stopping the Infrastructure

```bash
cd docker
docker compose down
```

To also remove volumes (data reset):

```bash
docker compose down -v
```

---

## 14. Troubleshooting

**Jenkins can't connect to Docker**
- Ensure the `dind` container is running: `docker ps`
- Check certs volume is shared correctly

**SonarQube won't start**
- Increase vm.max_map_count: `sudo sysctl -w vm.max_map_count=262144`

**Scanner not found**
- Install the missing tool on the Jenkins agent or add it to the Dockerfile

**Pipeline fails at a scanner stage**
- All scanners use `|| true` to avoid failing the pipeline on findings
- Check the console output for installation errors

**Empty report**
- Ensure at least one scanner ran and produced output in `reports/`
- Check that `profile.json` was generated in the profiling stage
