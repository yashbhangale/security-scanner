FROM jenkins/jenkins:lts-jdk21

USER root

RUN apt-get update && \
    apt-get install -y git curl wget unzip && \
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

USER jenkins

RUN jenkins-plugin-cli --plugins \
    blueocean \
    docker-workflow \
    workflow-aggregator \
    git \
    github \
    pipeline-stage-view
