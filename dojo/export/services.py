from dojo import __version__
from dojo.location.feature import locations_enabled
from dojo.models import System_Settings

EXPORT_API_VERSION = 1
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES_LIMIT = 64 * 1024 * 1024


def instance_id() -> str:
    return str(System_Settings.objects.get().instance_id)


def build_manifest(*, max_file_bytes: int) -> dict:
    return {
        "export_api_version": EXPORT_API_VERSION,
        "defectdojo_version": __version__,
        "instance_id": instance_id(),
        "locations_enabled": locations_enabled(),
        "max_file_bytes": max_file_bytes,
    }
