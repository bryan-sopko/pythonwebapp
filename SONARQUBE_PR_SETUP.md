# SonarQube PR Analysis Setup

This repository is configured for automated SonarQube analysis on Pull Requests.

## Prerequisites

- GitHub repository (push your code to GitHub)
- SonarQube server with PR decoration enabled
- GitHub Actions enabled on your repository

## Setup Instructions

### 1. Push to GitHub

```bash
# If you haven't added a remote yet
git remote add origin <your-github-repo-url>

# Push your code
git push -u origin main
git push origin feature/security-refactoring
```

### 2. Configure GitHub Secrets

Add these secrets to your GitHub repository (Settings → Secrets and variables → Actions):

- **`SONAR_TOKEN`**: Your SonarQube token
  - Value: `sqp_07a9719ec3f75f0a9cc88d1fbe01b1a5bbc0b2f1` (or generate a new one)
  
- **`SONAR_HOST_URL`**: Your SonarQube server URL
  - Value: `https://bryan-demo.ngrok.io`

### 3. Configure SonarQube Project

In your SonarQube server:

1. Go to **Administration → Configuration → General Settings → Pull Requests**
2. Set **Provider**: GitHub
3. Configure **GitHub integration**:
   - GitHub API URL: `https://api.github.com`
   - GitHub App ID (or use Personal Access Token)

4. Go to **Project Settings → General Settings → Pull Requests**
5. Enable **Decorate Pull Requests**

### 4. Create a Pull Request

```bash
# Make some changes on the feature branch
git checkout feature/security-refactoring

# Commit and push
git add .
git commit -m "Testing PR analysis"
git push origin feature/security-refactoring

# Create PR on GitHub
# Go to your GitHub repository and create a PR from feature/security-refactoring to main
```

## What Happens on PR

When you create or update a PR:

1. **GitHub Actions triggers** the SonarQube scan workflow
2. **Analysis runs** on the PR branch
3. **Results are posted** as PR comments showing:
   - Quality Gate status (Pass/Fail)
   - New issues introduced in the PR
   - Security vulnerabilities
   - Code coverage changes
4. **PR decoration** shows inline comments on affected lines

## Manual PR Scan (Local)

You can also run PR analysis locally:

```bash
sonar-scanner \
  -Dsonar.projectKey=python-demo \
  -Dsonar.sources=app \
  -Dsonar.host.url=https://bryan-demo.ngrok.io \
  -Dsonar.token=sqp_07a9719ec3f75f0a9cc88d1fbe01b1a5bbc0b2f1 \
  -Dsonar.pullrequest.key=<PR_NUMBER> \
  -Dsonar.pullrequest.branch=feature/security-refactoring \
  -Dsonar.pullrequest.base=main
```

## Files Created

- **`.github/workflows/sonarqube-pr-scan.yml`** - GitHub Actions workflow
- **`sonar-project.properties`** - SonarQube configuration
- **`SONARQUBE_PR_SETUP.md`** - This file

## Expected Results

Your PR will show all the vulnerabilities:
- ❌ 17 BLOCKER issues (SQL injection, XSS, exposed secrets)
- ❌ Security Rating: E
- ❌ Quality Gate: FAILED
- 0% test coverage

This is expected for this intentionally vulnerable demo application!
