pipeline {
    agent any

    parameters {
        string(name: 'REPO_URL', description: 'Git repository URL to scan')
        string(name: 'BRANCH', defaultValue: 'main', description: 'Branch to scan')
        string(name: 'EMAIL', defaultValue: '', description: 'Email address for report delivery')
        choice(name: 'SCAN_LEVEL', choices: ['full', 'basic'], description: 'Scan level: basic (trivy + gitleaks) or full (all scanners)')
        string(name: 'SONAR_PROJECT_KEY', defaultValue: '', description: 'SonarQube project key (leave empty to skip)')
    }

    environment {
        SCANNER_HOME = "${WORKSPACE}/security-scanner"
        TARGET_REPO  = "${WORKSPACE}/target-repo"
        REPORTS_DIR  = "${WORKSPACE}/target-repo/reports"
    }

    stages {

        stage('Cleanup') {
            steps {
                cleanWs()
            }
        }

        stage('Clone Scanner Repository') {
            steps {
                dir("${SCANNER_HOME}") {
                    checkout scm
                }
            }
        }

        stage('Clone Target Repository') {
            steps {
                dir("${TARGET_REPO}") {
                    git url: "${params.REPO_URL}", branch: "${params.BRANCH}"
                }
            }
        }

        stage('Project Profiling') {
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/project-profiler.sh"
                    sh "${SCANNER_HOME}/scripts/project-profiler.sh ."
                }
                script {
                    def profile = readJSON file: "${TARGET_REPO}/reports/profile.json"
                    env.SCANNERS = profile.scanners.join(',')
                    env.LANGUAGES = profile.languages.join(',')
                    env.TECHNOLOGIES = profile.technologies.join(',')
                    echo "Detected Languages: ${env.LANGUAGES}"
                    echo "Detected Technologies: ${env.TECHNOLOGIES}"
                    echo "Recommended Scanners: ${env.SCANNERS}"
                }
            }
        }

        stage('Filesystem Scan (Trivy)') {
            when {
                expression { env.SCANNERS.contains('trivy') }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/trivy.sh"
                    sh "${SCANNER_HOME}/scripts/trivy.sh"
                }
            }
        }

        stage('Secret Scan (Gitleaks)') {
            when {
                expression { env.SCANNERS.contains('gitleaks') }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/gitleaks.sh"
                    sh "${SCANNER_HOME}/scripts/gitleaks.sh"
                }
            }
        }

        stage('Static Analysis (Semgrep)') {
            when {
                expression {
                    env.SCANNERS.contains('semgrep') && params.SCAN_LEVEL == 'full'
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/semgrep.sh"
                    sh "${SCANNER_HOME}/scripts/semgrep.sh"
                }
            }
        }

        stage('Code Quality (SonarQube)') {
            when {
                expression {
                    env.SCANNERS.contains('sonar') && params.SCAN_LEVEL == 'full' && params.SONAR_PROJECT_KEY != ''
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/sonar.sh"
                    sh "${SCANNER_HOME}/scripts/sonar.sh ${params.SONAR_PROJECT_KEY}"
                }
            }
        }

        stage('SBOM Generation (Syft)') {
            when {
                expression {
                    env.SCANNERS.contains('syft') && params.SCAN_LEVEL == 'full'
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/syft.sh"
                    sh "${SCANNER_HOME}/scripts/syft.sh"
                }
            }
        }

        stage('Dependency Scan (Grype)') {
            when {
                expression {
                    env.SCANNERS.contains('grype') && params.SCAN_LEVEL == 'full'
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/grype.sh"
                    sh "${SCANNER_HOME}/scripts/grype.sh"
                }
            }
        }

        stage('IaC Scan (Checkov)') {
            when {
                expression {
                    env.SCANNERS.contains('checkov') && params.SCAN_LEVEL == 'full'
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/checkov.sh"
                    sh "${SCANNER_HOME}/scripts/checkov.sh"
                }
            }
        }

        stage('Dockerfile Scan (Hadolint)') {
            when {
                expression {
                    env.SCANNERS.contains('hadolint') && params.SCAN_LEVEL == 'full'
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/hadolint.sh"
                    sh "${SCANNER_HOME}/scripts/hadolint.sh"
                }
            }
        }

        stage('Kubernetes Scan (kube-linter)') {
            when {
                expression {
                    env.SCANNERS.contains('kube-linter') && params.SCAN_LEVEL == 'full'
                }
            }
            steps {
                dir("${TARGET_REPO}") {
                    sh "chmod +x ${SCANNER_HOME}/scripts/kube-linter.sh"
                    sh "${SCANNER_HOME}/scripts/kube-linter.sh"
                }
            }
        }

        stage('Generate Report') {
            steps {
                dir("${TARGET_REPO}") {
                    sh "python3 ${SCANNER_HOME}/scripts/report.py --reports-dir reports --template ${SCANNER_HOME}/templates/report.html --output reports/report.html"
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'target-repo/reports/**/*', allowEmptyArchive: true
                publishHTML(target: [
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'target-repo/reports',
                    reportFiles: 'report.html',
                    reportName: 'Security Scan Report'
                ])
            }
        }

        stage('Notify') {
            when {
                expression { params.EMAIL != '' }
            }
            steps {
                emailext(
                    subject: "Security Scan Report - ${params.REPO_URL}",
                    body: '''<p>Security scan completed for <b>${REPO_URL}</b> (branch: ${BRANCH}).</p>
                             <p>Please find the report attached or view it in Jenkins.</p>''',
                    to: "${params.EMAIL}",
                    attachmentsPattern: 'target-repo/reports/report.html',
                    mimeType: 'text/html'
                )
            }
        }
    }

    post {
        always {
            echo "Pipeline completed. Reports available in archived artifacts."
        }
        failure {
            echo "Pipeline encountered errors. Check stage logs for details."
        }
        success {
            echo "All scans completed successfully."
        }
    }
}
