import sys
from pathlib import Path

HEARTBEAT_FILE = Path("/tmp/celery_live")
if not HEARTBEAT_FILE.is_file():
    sys.exit(1)
sys.exit(0)