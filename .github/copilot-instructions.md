# DefectDojo - Django Security Vulnerability Management Platform

DefectDojo is a Django-based web application for vulnerability management and security testing orchestration. It supports Docker-based development with PostgreSQL and Redis.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites
- Docker and Docker Compose v2 (minimum Docker 19.03.0, Docker Compose 1.28.0)
- Check compatibility: `./docker/docker-compose-check.sh`

### Bootstrap and Initial Setup
**NEVER CANCEL: Initial startup takes 90+ seconds. NEVER CANCEL. Set timeout to 180+ seconds.**

1. **Check Docker compatibility:**
   ```bash
   ./docker/docker-compose-check.sh
   ```

2. **Set development environment:**
   ```bash
   ./docker/setEnv.sh dev
   ```

3. **Pull pre-built images (RECOMMENDED):**
   ```bash
   docker pull defectdojo/defectdojo-django:latest
   docker pull defectdojo/defectdojo-nginx:latest
   ```
   **NOTE:** Building from source fails in sandboxed environments due to SSL certificate issues. Always use pre-built images.

4. **Start the application (first time):**
   ```bash
   docker compose up -d
   ```
   **NEVER CANCEL: Takes 90 seconds for initialization. Set timeout to 180+ seconds.**

5. **Set admin password manually:**
   ```bash
   docker compose exec uwsgi ./manage.py shell -c 'from django.contrib.auth.models import User; u = User.objects.get(username="admin"); u.set_password("Password123!"); u.save()'
   ```

6. **Access the application:**
   - Navigate to `http://localhost:8080`
   - Login: username `admin`, password `Password123!`

### Subsequent Startups
**NEVER CANCEL: Startup takes 10+ seconds. Set timeout to 30+ seconds.**

1. **Disable database re-initialization:**
   ```bash
   export DD_INITIALIZE=false
   docker compose up -d
   ```
   **NEVER CANCEL: Takes 10 seconds. Set timeout to 30+ seconds.**

### Build and Test Commands

#### Unit Tests
**NEVER CANCEL: Unit tests take 60+ seconds. Set timeout to 120+ seconds.**

```bash
# Run specific test
./run-unittest.sh --test-case unittests.test_utils.TestUtils.test_encryption

# Available test modules: check unittests/ directory
# Example working test cases:
# - unittests.test_utils.TestUtils.test_encryption
# - unittests.test_utils.TestUtils.test_user_post_save_without_template
```

#### Integration Tests
**NEVER CANCEL: Integration tests take 120+ seconds. Set timeout to 300+ seconds.**

```bash
# Run specific integration test
./run-integration-tests.sh --test-case "tests/finding_test.py"
```

#### Environment Management
Switch between different Docker Compose profiles:
```bash
# Development mode (hot-reloading enabled)
./docker/setEnv.sh dev

# Unit testing mode
./docker/setEnv.sh unit_tests

# Integration testing mode  
./docker/setEnv.sh integration_tests

# Release mode
./docker/setEnv.sh release
```

### Cleanup
```bash
# Stop containers only
docker compose down

# Stop and remove data volumes
docker compose down --volumes
```

## Known Issues and Workarounds

### Building from Source
- **Issue:** `docker compose build` fails with SSL certificate verification errors in sandboxed environments
- **Workaround:** Always use pre-built images: `docker pull defectdojo/defectdojo-django:latest`

### Network Resolution Issues
- **Issue:** Nginx may fail to resolve `uwsgi:3031` on startup, causing nginx to exit
- **Workaround:** Restart nginx container: `docker compose restart nginx`
- **Alternative:** Start services sequentially instead of all at once

### Admin Password Generation
- **Issue:** Initializer may not always generate/display admin password in logs
- **Workaround:** Set password manually using Django shell command (shown above)

## Validation Workflow
Always follow this sequence when making changes:

1. **Test unit tests:**
   ```bash
   ./run-unittest.sh --test-case unittests.test_utils.TestUtils.test_encryption
   ```

2. **Test application startup:**
   ```bash
   docker compose down
   docker compose up -d
   # Wait 90 seconds for initialization
   ```

3. **Verify application access:**
   - Check `http://localhost:8080` is accessible
   - Verify login with admin credentials

4. **For significant changes, run integration tests:**
   ```bash
   ./run-integration-tests.sh --test-case "tests/finding_test.py"
   ```

## Development Notes

### Hot-Reloading (Development Mode)
- Code changes in `dojo/` directory automatically reload
- Static file changes require browser refresh (Ctrl+F5)
- Database schema changes require migrations: `docker compose exec uwsgi ./manage.py makemigrations`

### Database Access
- PostgreSQL accessible on `localhost:5432`
- Credentials: `defectdojo/defectdojo/defectdojo`
- Django shell: `docker compose exec uwsgi ./manage.py shell`

### Useful Commands
```bash
# View logs
docker compose logs uwsgi
docker compose logs nginx
docker compose logs initializer

# Container status
docker compose ps

# Execute commands in container
docker compose exec uwsgi bash
docker compose exec uwsgi ./manage.py --help
```

## Repository Structure

### Key Directories
- `dojo/` - Main Django application code
- `unittests/` - Unit test files
- `tests/` - Integration test files
- `docker/` - Docker configuration and scripts
- `requirements.txt` - Python dependencies

### Important Files
- `manage.py` - Django management script
- `docker-compose.yml` - Main Docker Compose configuration
- `docker-compose.override.*.yml` - Environment-specific overrides
- `./docker/setEnv.sh` - Environment switching script
- `./run-unittest.sh` - Unit test runner
- `./run-integration-tests.sh` - Integration test runner

## Timing Expectations
- **Docker image pull:** 60-120 seconds
- **Initial application startup:** 90 seconds (NEVER CANCEL)
- **Subsequent startup:** 10 seconds (NEVER CANCEL)
- **Single unit test:** 60 seconds (NEVER CANCEL)
- **Integration test:** 120+ seconds (NEVER CANCEL)
- **Environment switch:** 5 seconds

Always use appropriate timeouts and never cancel long-running operations.