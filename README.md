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

## Troubleshooting
- Check workflow logs for detailed error messages.
- Verify SSH keys and firewall rules on the remote server.
