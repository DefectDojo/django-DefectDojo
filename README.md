# CI/CD Pipeline for My Application

## Overview
This repository contains the source code and configuration for a CI/CD pipeline using GitHub Actions.

## CI/CD Stages
1. **Build**: Builds a Docker image and pushes it to Docker Hub.
2. **Test**: Runs automated tests using pytest.
3. **Deploy**: Deploys the application to a remote server using SSH.

## Requirements
- GitHub account with Actions enabled.
- Remote server with Docker installed.
- SSH access to the remote server.

## Configuration
1. Add the following secrets in GitHub Actions settings:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN`
   - `DEPLOY_SERVER_HOST`
   - `DEPLOY_SERVER_USER`
   - `DEPLOY_SERVER_KEY`
   - `DEPLOY_SERVER_PORT`

2. Ensure that the remote server has Docker installed and is accessible via SSH.

# Troubleshooting

## Common Issues
- **Missing `requirements.txt`**: If the `requirements.txt` file is missing, the Safety check will be skipped.
- **Bandit Report Not Found**: Ensure that Bandit generates the `bandit_report.json` file during execution.
- **CodeQL Language Support**: Make sure your project contains Python code for CodeQL analysis.

## Debugging Tips
- Review the logs in the GitHub Actions tab for detailed error messages.
- Ensure all required files (e.g., `requirements.txt`) are present in the repository.
- Update dependencies to fix vulnerabilities reported by Safety.

# DAST Integration with Nikto

## Overview
This project integrates Dynamic Application Security Testing (DAST) into the GitHub Actions CI/CD pipeline using Nikto.

## Tools Used
- **Nikto**: For scanning web servers for known vulnerabilities.

## Workflow
1. **Application Scanning**: Nikto scans the web server for vulnerabilities.
2. **Report Generation**: Results are saved as a text file in the `reports/` directory.
3. **Optional**: Results can be sent to a vulnerability management system for further analysis.

## Results
- DAST reports are available in the GitHub Actions logs.
- Reports can be downloaded from artifacts for further analysis.

## Troubleshooting
- Ensure that the `DAST_TARGET_URL` secret points to a valid and accessible URL.
- Verify that your application is fully started and accessible at the specified URL.
- Update the `sleep` duration in the pipeline if your application requires more time to start.

# Unit Tests Workflow for Django

## Environment Configuration
The pipeline now creates a `.env` file automatically during testing using proper `here-document` syntax. This ensures that the pipeline works without requiring a separate `.env.example` file.

### Example `.env` Content
The following variables are set in the `.env` file created by the pipeline:
- `DEBUG=True`
- `SECRET_KEY=your_secret_key_for_testing`
- `DATABASE_URL=postgres://postgres:postgres@localhost:5432/testdb`

## Debugging Tips
- Ensure that your project contains test files (e.g., `tests.py`) with valid test cases.
- If you encounter issues with database migrations, verify your database settings in `settings.py`.
- Review the logs in the GitHub Actions tab for detailed error messages.
