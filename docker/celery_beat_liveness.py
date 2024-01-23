import sys
from pathlib import Path

PID_FILE = Path("/tmp/celery-beat.pid")
if not PID_FILE.is_file():
    print("Celery beat PID file NOT found.")
    sys.exit(1)
print("Celery beat PID file found.")
sys.exit(0)
