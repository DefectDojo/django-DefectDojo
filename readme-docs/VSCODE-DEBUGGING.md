# VS Code Debugging Setup for DefectDojo

This guide explains how to set up VS Code for debugging DefectDojo's Django Python code using remote debugging with `debugpy`. You'll be able to set breakpoints, step through code, inspect variables, and debug the Django application running inside Docker containers.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
  - [1. Configure VS Code](#1-configure-vs-code)
  - [2. Start DefectDojo in Debug Mode](#2-start-defectdojo-in-debug-mode)
  - [3. Connect VS Code Debugger](#3-connect-vs-code-debugger)
- [Debugging Workflow](#debugging-workflow)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

## Prerequisites

Before you begin, ensure you have:

- [Docker and Docker Compose v2](https://docs.docker.com/compose/install/) (minimum Docker 19.03.0, Docker Compose 1.28.0)
- [Visual Studio Code](https://code.visualstudio.com/)
- [Python extension for VS Code](https://marketplace.visualstudio.com/items?itemName=ms-python.python)
- DefectDojo repository cloned locally

## Quick Start

1. **Setup environment and start in debug mode:**
   ```bash
   # Check Docker compatibility
   ./docker/docker-compose-check.sh
   
   # Set debug environment
   ./docker/setEnv.sh debug
   
   # Start DefectDojo in debug mode (this will wait for debugger connection)
   docker compose up -d
   ```

2. **Connect VS Code debugger:**
   - Open DefectDojo project in VS Code
   - Go to Run and Debug view (Ctrl+Shift+D)
   - Select "Debug DefectDojo (Remote)" configuration
   - Press F5 or click the green play button

3. **Start debugging:**
   - The application will start after VS Code connects
   - Navigate to http://localhost:8080 to access DefectDojo
   - Set breakpoints in your Python code and they will be hit

## Detailed Setup

### 1. Configure VS Code

First, you need to create VS Code debugging configuration files in your DefectDojo project:

#### Create `.vscode/launch.json`

Create the `.vscode` directory in your project root if it doesn't exist, then create `launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug DefectDojo (Remote)",
            "type": "python",
            "request": "attach",
            "port": 5678,
            "host": "localhost",
            "pathMappings": [
                {
                    "localRoot": "${workspaceFolder}",
                    "remoteRoot": "/app"
                }
            ],
            "justMyCode": false,
            "django": true,
            "redirectOutput": true,
            "console": "integratedTerminal"
        }
    ]
}
```

#### Create `.vscode/settings.json` (Optional)

For better Python development experience:

```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true
    }
}
```

### 2. Start DefectDojo in Debug Mode

#### Method 1: Using the setEnv.sh script (Recommended)

```bash
# Set the debug environment (creates symlink to docker-compose.override.debug.yml)
./docker/setEnv.sh debug

# Start all services in debug mode
docker compose up -d
```

#### Method 2: Manual setup

```bash
# Create symlink to debug override file
rm -f docker-compose.override.yml
ln -s docker-compose.override.debug.yml docker-compose.override.yml

# Start the services
docker compose up -d
```

**Important:** The Django application will wait for a debugger to connect before starting. You'll see a message like:

```
uwsgi-1  | Debug mode enabled with debugpy support
uwsgi-1  | Debugpy server will listen on 0.0.0.0:5678
uwsgi-1  | Connect your VS Code debugger to localhost:5678
```

### 3. Connect VS Code Debugger

1. **Open the project in VS Code:**
   ```bash
   code .
   ```

2. **Open the Run and Debug view:**
   - Press `Ctrl+Shift+D` (Windows/Linux) or `Cmd+Shift+D` (Mac)
   - Or click the Run and Debug icon in the Activity Bar

3. **Select the debug configuration:**
   - In the Run and Debug view, select "Debug DefectDojo (Remote)" from the dropdown

4. **Start debugging:**
   - Press `F5` or click the green play button
   - VS Code will connect to the remote debugger
   - The Django application will start after the connection is established

## Debugging Workflow

### Setting Breakpoints

1. **Open any Python file** in the DefectDojo project (e.g., `dojo/views.py`, `dojo/models.py`)
2. **Click in the gutter** next to line numbers to set breakpoints (red dots will appear)
3. **Navigate to the application** at http://localhost:8080 to trigger your breakpoints

### Debugging Features

Once connected, you can use all VS Code debugging features:

- **Step Over (F10):** Execute the current line
- **Step Into (F11):** Step into function calls
- **Step Out (Shift+F11):** Step out of current function
- **Continue (F5):** Continue execution until next breakpoint
- **Variables:** Inspect local and global variables
- **Call Stack:** View the current call stack
- **Debug Console:** Execute Python expressions in the current context
- **Watch:** Monitor specific expressions

### Example: Debugging a View

1. Open `dojo/finding/views.py`
2. Set a breakpoint on a view function (e.g., `def view_finding()`)
3. Navigate to a finding in the web interface
4. The debugger will pause at your breakpoint
5. Inspect variables, step through code, etc.

## Troubleshooting

### Common Issues

#### 1. Connection Refused
**Problem:** VS Code can't connect to debugpy server

**Solutions:**
- Ensure Docker containers are running: `docker compose ps`
- Check if debugpy port is exposed: `docker compose port uwsgi 5678`
- Verify logs: `docker compose logs uwsgi`

#### 2. Application Not Starting
**Problem:** DefectDojo doesn't start after debugger connects

**Solutions:**
- Check container logs: `docker compose logs uwsgi`
- Ensure all containers are healthy: `docker compose ps`
- Restart the services: `docker compose restart`

#### 3. Breakpoints Not Working
**Problem:** Breakpoints are ignored or show as unbound

**Solutions:**
- Verify path mappings in `launch.json` are correct
- Ensure you're debugging the correct Python process
- Check that the file paths match between local and container
- Set `"justMyCode": false` in launch.json to debug into libraries

#### 4. Performance Issues
**Problem:** Application runs slowly during debugging

**Solutions:**
- Use conditional breakpoints for high-frequency code
- Disable unnecessary breakpoints
- Use "Step Over" instead of "Step Into" for library calls

#### 5. Database Connection Issues
**Problem:** Database not accessible during debugging

**Solutions:**
- Ensure all containers started properly: `docker compose up -d`
- Check database container: `docker compose logs postgres`
- Verify database initialization: `docker compose logs initializer`

### Debug Port Already in Use

If port 5678 is already in use, you can change it:

1. Update `docker-compose.override.debug.yml`:
   ```yaml
   ports:
     - target: 5679  # Change to different port
       published: 5679
   ```

2. Update the debug entrypoint script to use the new port
3. Update VS Code `launch.json` to match the new port

### Checking Container Status

```bash
# View all container status
docker compose ps

# View uwsgi container logs
docker compose logs uwsgi

# Follow uwsgi logs in real-time
docker compose logs -f uwsgi

# Restart uwsgi container
docker compose restart uwsgi
```

## Advanced Configuration

### Debugging Specific Services

You can modify the debug setup to debug other services like Celery workers:

#### Debugging Celery Workers

1. Add debugpy configuration to `celeryworker` service in `docker-compose.override.debug.yml`
2. Expose a different port for the Celery debugger
3. Create a separate VS Code launch configuration

### Environment Variables

Key environment variables for debugging:

- `DD_DEBUG=True`: Enables Django debug mode
- `PYTHONWARNINGS=error`: Treats warnings as errors during development

### Using Django Debug Toolbar

For additional debugging capabilities, you can enable Django Debug Toolbar:

1. Create `dojo/settings/local_settings.py` based on the template
2. Enable debug toolbar in the settings
3. Rebuild the Docker images

### Debugging with PyCharm

While this guide focuses on VS Code, you can adapt the setup for PyCharm:

1. Use the same `debugpy` server configuration
2. Configure PyCharm's remote Python interpreter
3. Set up remote debugging configuration pointing to `localhost:5678`

## Additional Resources

- [VS Code Python Debugging](https://code.visualstudio.com/docs/python/debugging)
- [Django Debugging Documentation](https://docs.djangoproject.com/en/stable/topics/logging/)
- [debugpy Documentation](https://github.com/microsoft/debugpy)
- [DefectDojo Docker Documentation](../readme-docs/DOCKER.md)

## Tips for Effective Debugging

1. **Use conditional breakpoints** for code that runs frequently
2. **Set breakpoints in exception handlers** to catch errors early
3. **Use the debug console** to test expressions and modify variables
4. **Leverage the call stack** to understand code flow
5. **Use logging** in combination with breakpoints for better insight
6. **Keep the debug session focused** - too many breakpoints can slow things down

## Switching Back to Development Mode

When you're done debugging and want to return to normal development mode:

```bash
# Switch back to development mode
./docker/setEnv.sh dev

# Restart the services
docker compose up -d
```

This will switch back to the regular hot-reloading development setup without debugpy.