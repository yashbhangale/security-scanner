FROM jenkins/jenkins:lts-jdk21

USER root

RUN apt-get update && \
    apt-get install -y git curl wget unzip python3 python3-pip && \
    apt-get clean

# Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg \
| tee /etc/apt/keyrings/docker.asc >/dev/null && \
chmod a+r /etc/apt/keyrings/docker.asc && \
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
> /etc/apt/sources.list.d/docker.list && \
apt-get update && \
apt-get install -y docker-ce-cli

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks
RUN GITLEAKS_VERSION="8.21.2" && \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz" -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Hadolint
RUN wget -q https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 -O /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# kube-linter
RUN KUBELINTER_VERSION="0.7.1" && \
    wget -q "https://github.com/stackrox/kube-linter/releases/download/v${KUBELINTER_VERSION}/kube-linter-linux" -O /usr/local/bin/kube-linter && \
    chmod +x /usr/local/bin/kube-linter

# Semgrep + Checkov (Python tools)
RUN pip install --break-system-packages semgrep checkov

USER jenkins

RUN jenkins-plugin-cli --plugins \
    blueocean \
    docker-workflow \
    workflow-aggregator \
    git \
    github \
    pipeline-stage-view \
    pipeline-utility-steps \
    htmlpublisher \
    email-ext
