For your project, I recommend using **Docker Compose** instead of multiple `docker run` commands. It's cleaner and easier to maintain.

---

# 1. Check Docker

```bash
docker --version
docker compose version
```

---

# 2. Create Project

```bash
mkdir security-scanner
cd security-scanner

mkdir jenkins
cd jenkins
```

---

# 3. Create Dockerfile

```bash
touch Dockerfile
```

Paste the Dockerfile content.

---

# 4. Build Jenkins Image

```bash
docker build -t myjenkins .
```

Verify:

```bash
docker images
```

---

# 5. Create Network

```bash
docker network create jenkins
```

List networks:

```bash
docker network ls
```

Inspect:

```bash
docker network inspect jenkins
```

---

# 6. Start Docker-in-Docker

```bash
docker run -d \
--name jenkins-docker \
--restart unless-stopped \
--privileged \
--network jenkins \
--network-alias docker \
-e DOCKER_TLS_CERTDIR=/certs \
-v jenkins-docker-certs:/certs/client \
-v jenkins-data:/var/jenkins_home \
docker:dind
```

Check:

```bash
docker ps
```

Logs:

```bash
docker logs jenkins-docker
```

---

# 7. Start Jenkins

```bash
docker run -d \
--name jenkins \
--restart unless-stopped \
--network jenkins \
-e DOCKER_HOST=tcp://docker:2376 \
-e DOCKER_CERT_PATH=/certs/client \
-e DOCKER_TLS_VERIFY=1 \
-p 8080:8080 \
-p 50000:50000 \
-v jenkins-data:/var/jenkins_home \
-v jenkins-docker-certs:/certs/client:ro \
myjenkins
```

Check:

```bash
docker ps
```

---

# 8. View Logs

```bash
docker logs -f jenkins
```

---

# 9. Initial Password

```bash
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

Open:

```
http://localhost:8080
```

---

# 10. Install Suggested Plugins

* Git
* Pipeline
* Docker Pipeline
* Blue Ocean
* GitHub
* SonarQube Scanner
* HTML Publisher

---

# 11. Verify Docker Works

```bash
docker exec -it jenkins bash
```

Inside:

```bash
docker version
docker ps
exit
```

---

# 12. Start SonarQube

```bash
docker run -d \
--name sonarqube \
--network jenkins \
-p 9000:9000 \
sonarqube:lts-community
```

Check:

```bash
docker ps
docker logs sonarqube
```

Open:

```
http://localhost:9000
```

Login:

```
admin
admin
```

---

# Docker Commands You'll Use Daily

## Running Containers

```bash
docker ps
```

All containers

```bash
docker ps -a
```

---

## Stop

```bash
docker stop jenkins
```

Start

```bash
docker start jenkins
```

Restart

```bash
docker restart jenkins
```

---

## View Logs

```bash
docker logs jenkins
```

Live logs

```bash
docker logs -f jenkins
```

---

## Enter Container

```bash
docker exec -it jenkins bash
```

Exit

```bash
exit
```

---

## Remove Container

```bash
docker rm -f jenkins
```

---

## List Images

```bash
docker images
```

Delete Image

```bash
docker rmi myjenkins
```

---

## List Volumes

```bash
docker volume ls
```

Inspect

```bash
docker volume inspect jenkins-data
```

Delete

```bash
docker volume rm jenkins-data
```

---

## Networks

List

```bash
docker network ls
```

Inspect

```bash
docker network inspect jenkins
```

Delete

```bash
docker network rm jenkins
```

---

## Copy Files

Host → Jenkins

```bash
docker cp test.txt jenkins:/tmp
```

Jenkins → Host

```bash
docker cp jenkins:/tmp/test.txt .
```

---

# Jenkins Backup

Backup Jenkins home:

```bash
docker run --rm \
-v jenkins-data:/data \
-v $(pwd):/backup \
ubuntu \
tar czf /backup/jenkins-backup.tar.gz /data
```

Restore:

```bash
tar -xzf jenkins-backup.tar.gz
```

---

# Updating Jenkins

Pull latest base image:

```bash
docker pull jenkins/jenkins:lts-jdk21
```

Rebuild:

```bash
docker build -t myjenkins .
```

Restart:

```bash
docker rm -f jenkins
```

Run again using the same `docker run` command.

---

# Useful Jenkins CLI Paths

Inside the container:

```text
/var/jenkins_home/jobs
/var/jenkins_home/plugins
/var/jenkins_home/secrets
/var/jenkins_home/workspace
```

---

## Suggested Learning Roadmap

1. Install Jenkins
2. Create a Freestyle Job
3. Learn Pipeline syntax (`Jenkinsfile`)
4. Integrate GitHub
5. Build a project on commit
6. Add SonarQube
7. Add Trivy
8. Add Gitleaks
9. Generate HTML reports
10. Send Slack/Email notifications
11. Parameterize builds (e.g., `REPO_URL`, `BRANCH`)
12. Build your generic "Security Scan as a Service" pipeline

This progression will take you from basic Jenkins usage to the reusable security scanning platform you described.
