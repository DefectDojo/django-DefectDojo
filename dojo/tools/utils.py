import io
import json
import logging
import zipfile

from django.conf import settings

logger = logging.getLogger(__name__)


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

    if len(infos) > settings.MAX_ZIP_MEMBERS:
        zf.close()
        msg = f"Zip file contains {len(infos)} members, exceeding the limit of {settings.MAX_ZIP_MEMBERS}."
        raise ValueError(msg)

    total_size = 0
    for info in infos:
        if info.file_size > settings.MAX_ZIP_MEMBER_SIZE:
            zf.close()
            msg = (
                f"Zip member '{info.filename}' has uncompressed size {info.file_size} bytes, "
                f"exceeding the per-member limit of {settings.MAX_ZIP_MEMBER_SIZE} bytes."
            )
            raise ValueError(msg)
        if info.compress_size > 0 and (info.file_size / info.compress_size) > settings.MAX_ZIP_RATIO:
            zf.close()
            ratio = info.file_size / info.compress_size
            msg = (
                f"Zip member '{info.filename}' has a compression ratio of "
                f"{ratio:.1f}:1, exceeding the limit of {settings.MAX_ZIP_RATIO}:1."
            )
            raise ValueError(msg)
        total_size += info.file_size
        if total_size > settings.MAX_ZIP_TOTAL_SIZE:
            zf.close()
            msg = f"Zip file total uncompressed size exceeds the limit of {settings.MAX_ZIP_TOTAL_SIZE} bytes."
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


def get_npm_cwes(item_node):
    """
    Return the full list of CWE integers for an npm/yarn advisory node.

    Possible input values for item_node["cwe"]:
        "cwe": null
        "cwe": ["CWE-173", "CWE-200","CWE-601"]  (or [])
        "cwe": "CWE-1234"
        "cwe": '["CWE-173","CWE-200","CWE-601"]' (or "[]")

    Returns a list of ints (may be empty when no CWE is present).
    """
    cwe_node = item_node.get("cwe")
    if cwe_node:
        if isinstance(cwe_node, list):
            return [int(cwe[4:]) for cwe in cwe_node if cwe]
        if cwe_node.startswith("CWE-"):
            cwe_string = cwe_node[4:]
            if cwe_string:
                return [int(cwe_string)]
        elif cwe_node.startswith("["):
            cwe = json.loads(cwe_node)
            if cwe:
                return [int(c[4:]) for c in cwe if c]
    return []


def get_npm_cwe(item_node):
    """
    Return the primary (first) CWE integer for an npm/yarn advisory node.

    Possible values:
        "cwe": null
        "cwe": ["CWE-173", "CWE-200","CWE-601"]  (or [])
        "cwe": "CWE-1234"
        "cwe": '["CWE-173","CWE-200","CWE-601"]' (or "[]")
    """
    cwes = get_npm_cwes(item_node)
    if cwes:
        return cwes[0]

    # Use CWE-1035 as fallback (vulnerable third party component)
    return 1035


def drop_repeated_unique_ids(items):
    """
    Drop a `unique_id_from_tool` that more than one finding in the same report carries.

    A unique id that repeats inside its own report is not an identity. Scanners emit
    constant placeholders (a live SARIF report carried the literal string "requires
    login" on eleven findings), SARIF partial fingerprints hash line content so identical
    lines collide, and a multi-location result becomes one finding per location, each
    holding the result's single fingerprint. Downstream deduplication trusts
    `unique_id_from_tool` equality, so keeping the value would merge findings that are
    visibly different. Findings whose id is dropped deduplicate by hash code, exactly
    like findings the scanner gave no id.
    """
    from collections import Counter  # noqa: PLC0415

    counts = Counter(item.unique_id_from_tool for item in items if item.unique_id_from_tool)
    repeated = {value for value, count in counts.items() if count > 1}
    for item in items:
        if item.unique_id_from_tool in repeated:
            item.unique_id_from_tool = None
    return items
