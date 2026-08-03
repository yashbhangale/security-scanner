# Security Scanner - Project Documentation

## Overview

**Security Scanner** is a DevSecOps automation platform that scans any Git repository using a single generic Jenkins pipeline.

Instead of configuring security tools for every project, users only provide a repository URL. The platform automatically profiles the project, selects the relevant scanners, executes them, aggregates the results, and generates a comprehensive security report.

---

# Objectives

* Scan any Git repository using a single Jenkins pipeline.
* Automatically detect project type and technologies.
* Run only relevant security scanners.
* Generate consolidated security reports.
* Make the scanner reusable across organizations and repositories.

---

# High-Level Architecture

```text
                         User
                           │
                    Repository URL
                           │
                           ▼
                    Jenkins Pipeline
                           │
                           ▼
                Clone Target Repository
                           │
                           ▼
                  Project Profiler
                           │
      ┌────────────────────┼────────────────────┐
      │                    │                    │
      ▼                    ▼                    ▼
 Detect Language     Detect Frameworks   Detect Infrastructure
      │                    │                    │
      └────────────────────┼────────────────────┘
                           ▼
                   Scanner Engine
      ┌────────────────────────────────────────────┐
      │ Trivy                                      │
      │ Gitleaks                                   │
      │ Semgrep                                    │
      │ SonarQube                                  │
      │ Syft                                       │
      │ Grype                                      │
      │ Checkov                                    │
      │ Hadolint                                   │
      │ kube-linter                                │
      └────────────────────────────────────────────┘
                           │
                           ▼
                   Result Aggregator
                           │
                           ▼
              HTML / JSON / SARIF / SBOM
                           │
                           ▼
               Jenkins / Email / Slack
```

---

# Technology Stack

| Category            | Technology               |
| ------------------- | ------------------------ |
| CI/CD               | Jenkins                  |
| SCM                 | GitHub                   |
| Scripting           | Bash, Python             |
| Containerization    | Docker                   |
| Security Scanners   | Trivy, Gitleaks, Semgrep |
| SAST                | SonarQube                |
| Dependency Analysis | Syft, Grype              |
| IaC                 | Checkov                  |
| Docker              | Hadolint                 |
| Kubernetes          | kube-linter              |
| Reporting           | HTML, JSON, SARIF        |

---

# Project Structure

```text
security-scanner/
│
├── Jenkinsfile
├── README.md
├── LICENSE
├── .gitignore
│
├── scripts/
│   ├── project-profiler.sh
│   ├── trivy.sh
│   ├── gitleaks.sh
│   ├── semgrep.sh
│   ├── sonar.sh
│   ├── syft.sh
│   ├── grype.sh
│   ├── checkov.sh
│   ├── hadolint.sh
│   └── report.py
│
├── templates/
│   └── report.html
│
├── reports/
│
├── docs/
│
├── sample-output/
│
└── docker/
```

---

# Pipeline Workflow

```text
Start

↓

Cleanup Workspace

↓

Clone Target Repository

↓

Project Profiling

↓

Filesystem Scan (Trivy)

↓

Secret Scan (Gitleaks)

↓

Static Analysis (Semgrep)

↓

Code Quality (SonarQube)

↓

SBOM Generation (Syft)

↓

Dependency Vulnerability Scan (Grype)

↓

IaC Scan (Checkov)

↓

Dockerfile Scan (Hadolint)

↓

Kubernetes Scan (kube-linter)

↓

Aggregate Results

↓

Generate HTML Report

↓

Archive Reports

↓

Notify User
```

---

# Project Profiler

The profiler determines how the repository should be scanned.

### Detects

### Programming Languages

* Go
* Java
* Node.js
* Python
* Rust
* PHP
* Ruby
* .NET

### Package Managers

* npm
* pnpm
* Yarn
* Maven
* Gradle
* Poetry
* Cargo
* Go Modules
* Composer

### Technologies

* Docker
* Docker Compose
* Kubernetes
* Helm
* Terraform
* GitHub Actions
* Jenkins
* GitLab CI
* ArgoCD
* Kustomize

### Repository Information

* Branch
* Commit Hash
* Remote URL
* File Count
* Directory Count

---

# Scanner Modules

## Trivy

Purpose

* Vulnerabilities
* Secrets
* Misconfigurations
* SBOM

Outputs

* JSON
* Table
* CycloneDX SBOM

---

## Gitleaks

Purpose

* Hardcoded Secrets

Outputs

* JSON

---

## Semgrep

Purpose

* Static Code Analysis

Outputs

* JSON

---

## SonarQube

Purpose

* Code Quality
* Maintainability
* Security Hotspots
* Code Smells
* Coverage

---

## Syft

Purpose

* Generate SBOM

Outputs

* SPDX
* CycloneDX

---

## Grype

Purpose

* Dependency Vulnerabilities

Uses

* SBOM

---

## Checkov

Purpose

* Infrastructure as Code Security

Supports

* Terraform
* Kubernetes
* Docker
* GitHub Actions

---

## Hadolint

Purpose

* Dockerfile Best Practices

---

## kube-linter

Purpose

* Kubernetes Manifest Validation

---

# Reports

Generated Reports

```text
reports/

├── trivy-report.json
├── trivy-report.txt
├── sbom.json
├── semgrep.json
├── gitleaks.json
├── sonar-report.json
├── report.html
```

---

# HTML Dashboard

Example

```text
Repository

Language

Security Score

Critical
High
Medium
Low

Secrets Found

Code Smells

Dependency Issues

Docker Issues

Terraform Issues

Kubernetes Issues

Download Reports
```

---

# Jenkins Parameters

| Parameter         | Description       |
| ----------------- | ----------------- |
| REPO_URL          | Repository URL    |
| BRANCH            | Branch to scan    |
| EMAIL             | Email report      |
| SCAN_LEVEL        | Basic / Full      |
| SONAR_PROJECT_KEY | SonarQube Project |

---

# Development Roadmap

## Phase 1 ✅

* Jenkins Installation
* Generic Pipeline
* Clone Repository

---

## Phase 2 🚧

* Project Profiler

---

## Phase 3

* Trivy

---

## Phase 4

* Parse Trivy Report

---

## Phase 5

* Gitleaks

---

## Phase 6

* Semgrep

---

## Phase 7

* SonarQube

---

## Phase 8

* Syft

---

## Phase 9

* Grype

---

## Phase 10

* Checkov

---

## Phase 11

* Hadolint

---

## Phase 12

* kube-linter

---

## Phase 13

* HTML Report Generator

---

## Phase 14

* Email Notifications

---



