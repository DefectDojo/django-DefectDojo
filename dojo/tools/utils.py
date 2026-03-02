import io
import json
import logging
import zipfile

logger = logging.getLogger(__name__)

# Zip bomb protection limits
MAX_ZIP_MEMBERS = 1000
MAX_ZIP_MEMBER_SIZE = 512 * 1024 * 1024  # 512 MB per member (uncompressed)
MAX_ZIP_TOTAL_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB total (uncompressed)
MAX_ZIP_RATIO = 100  # max compression ratio (uncompressed / compressed)


def safe_open_zip(file):
    """
    Open a zip file with protection against zip bomb attacks.

    Validates member count, per-member uncompressed size, total uncompressed
    size, and compression ratios using the central-directory metadata before
    any data is extracted.

    Accepts a file-like object or an io.TextIOWrapper (in which case
    file.name is used as the path).

    Returns an open ZipFile. Use as a context manager or call .close()
    explicitly when done.

    Raises ValueError if any limit is exceeded.
    """
    zf = zipfile.ZipFile(file.name, "r") if isinstance(file, io.TextIOWrapper) else zipfile.ZipFile(file, "r")

    infos = zf.infolist()

    if len(infos) > MAX_ZIP_MEMBERS:
        zf.close()
        msg = f"Zip file contains {len(infos)} members, exceeding the limit of {MAX_ZIP_MEMBERS}."
        raise ValueError(msg)

    total_size = 0
    for info in infos:
        if info.file_size > MAX_ZIP_MEMBER_SIZE:
            zf.close()
            msg = (
                f"Zip member '{info.filename}' has uncompressed size {info.file_size} bytes, "
                f"exceeding the per-member limit of {MAX_ZIP_MEMBER_SIZE} bytes."
            )
            raise ValueError(msg)
        if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_ZIP_RATIO:
            zf.close()
            ratio = info.file_size / info.compress_size
            msg = (
                f"Zip member '{info.filename}' has a compression ratio of "
                f"{ratio:.1f}:1, exceeding the limit of {MAX_ZIP_RATIO}:1."
            )
            raise ValueError(msg)
        total_size += info.file_size
        if total_size > MAX_ZIP_TOTAL_SIZE:
            zf.close()
            msg = f"Zip file total uncompressed size exceeds the limit of {MAX_ZIP_TOTAL_SIZE} bytes."
            raise ValueError(msg)

    return zf


def safe_read_all_zip(file):
    """
    Open a zip file safely and read all members into a dict {name: bytes}.

    Applies the same zip bomb protections as safe_open_zip before reading
    any data.

    Raises ValueError if any limit is exceeded.
    """
    zf = safe_open_zip(file)
    try:
        return {name: zf.read(name) for name in zf.namelist()}
    finally:
        zf.close()


def get_npm_cwe(item_node):
    """
    Possible values:
        "cwe": null
        "cwe": ["CWE-173", "CWE-200","CWE-601"]  (or [])
        "cwe": "CWE-1234"
        "cwe": '["CWE-173","CWE-200","CWE-601"]' (or "[]")
    """
    cwe_node = item_node.get("cwe")
    if cwe_node:
        if isinstance(cwe_node, list):
            return int(cwe_node[0][4:])
        if cwe_node.startswith("CWE-"):
            cwe_string = cwe_node[4:]
            if cwe_string:
                return int(cwe_string)
        elif cwe_node.startswith("["):
            cwe = json.loads(cwe_node)
            if cwe:
                return int(cwe[0][4:])

    # Use CWE-1035 as fallback (vulnerable third party component)
    return 1035
