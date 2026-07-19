"""
Structural authorization tripwire for API v3 (§5 I8, §10).

A **source-scan** (no DB, no HTTP) over the v3 route layer that converts "someone forgot the RBAC
check" from a silent runtime hole into a compile-time-ish failure with a named location. It
complements the behavioural sweep (``test_apiv3_authz_sweep.py``): the sweep proves the *current*
routes deny by default; this test proves every route is *structurally wired* to an authorization
primitive, so a new route that skips the check fails CI even before anyone writes a request for it.

Scanned files: ``dojo/*/api_v3/routes.py`` (every resource) + ``dojo/api_v3/import_routes.py`` +
``dojo/api_v3/subresources.py``.

Two rules:

**Rule A -- ban direct model-manager access.** Any source line containing ``.objects.`` fails unless
its ``Model.objects.method`` pattern is in ``OBJECTS_ALLOWLIST`` for that file, each entry carrying a
one-line justification. Reads MUST flow through the ``get_authorized_*`` querysets (I8); the only
legitimate ``.objects.`` uses are (a) edge reads from an already-authorized parent, (b) writes /
uniqueness pre-checks that run *after* an authorization gate, and (c) the users self-scope queryset
which *is* the RBAC mechanism. The allowlist is audited, never blanket -- and stale entries (allowing
a pattern that no longer occurs) fail too, so it cannot rot into a rubber stamp.

**Rule B -- require an authorization reference.** (1) Every scanned file must reference at least one
authorization primitive. (2) Every function *registered as a route operation* (decorated with
``@router.<verb>`` or registered via ``router.<verb>(path, ...)(fn)``) must reference an authorization
primitive **in its own body, or in a helper it calls within the same module** (one level of
indirection -- ``_base_queryset`` / ``_detail_object`` / ``_require`` / the import ``_resolve_*`` /
``_check_auto_permission`` helpers count). Failures name ``file::function``.

The authorization primitives (``AUTHZ_TOKENS``) are this codebase's real RBAC vocabulary: the
``get_authorized_*`` queryset helpers (``dojo/<resource>/queries.py``), the ``user_has_*`` permission
helpers (``dojo/authorization/authorization.py`` -- object / global / configuration), the route-local
``_require*`` gate helpers, and the ``is_superuser`` gate that faithfully mirrors v2's ``IsSuperUser``
class (§12 OS4).
"""
from __future__ import annotations

import ast
from pathlib import Path

from django.test import SimpleTestCase

# --- what to scan -----------------------------------------------------------------------------
# Repo root: unittests/api_v3/<thisfile> -> parents[2].
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _scanned_files() -> list[Path]:
    """Every v3 route module (resources are globbed so a new resource is auto-included)."""
    files = sorted((_REPO_ROOT / "dojo").glob("*/api_v3/routes.py"))
    files.append(_REPO_ROOT / "dojo" / "api_v3" / "import_routes.py")
    files.append(_REPO_ROOT / "dojo" / "api_v3" / "subresources.py")
    return files


# --- Rule A: the audited .objects. allowlist --------------------------------------------------
# Keys are (repo-relative posix path, "Model.objects.method"). Every entry was verified by reading
# the code: each such call either reads from an ALREADY-authorized parent, or runs a write /
# uniqueness check AFTER an authorization gate, or IS the RBAC scoping itself. Nothing here is an
# unauthorized object read. A ".objects." line whose pattern is absent here fails the test.
OBJECTS_ALLOWLIST: dict[tuple[str, str], str] = {
    ("dojo/location/api_v3/routes.py", "LocationFindingReference.objects.filter"):
        "edge rows read from a parent finding ALREADY resolved via get_authorized_findings "
        "(parent-inherited authz); mirrors the v2 LocationFindingReference viewset.",
    ("dojo/location/api_v3/routes.py", "LocationProductReference.objects.filter"):
        "edge rows read from a parent asset ALREADY resolved via get_authorized_products "
        "(parent-inherited authz); mirrors the v2 LocationProductReference viewset.",
    ("dojo/api_v3/subresources.py", "NoteHistory.objects.create"):
        "writes the NoteHistory row for a note just created on a parent that was authorized and "
        "permission-checked; a write of an owned sub-object, not an object read.",
    ("dojo/api_v3/subresources.py", "FileUpload.objects.filter"):
        "global title-uniqueness pre-check (mirrors DRF UniqueValidator -> 400) AFTER the parent "
        "authz + add-permission gate; not object disclosure.",
    ("dojo/user/api_v3/routes.py", "Dojo_User.objects.filter"):
        "the RBAC scoping itself: the self-only fallback queryset for users lacking auth.view_user "
        "(line 100) and the username-uniqueness check AFTER the auth.add_user gate (line 181).",
}

# --- Rule B: authorization primitives ---------------------------------------------------------
# Substrings that mark an authorization reference. `user_has_` covers the object / global /
# configuration permission helpers; `get_authorized_` the RBAC querysets; `_require` the route-local
# gate helpers (_require / _require_permission / _require_config_permission); `is_superuser` the
# faithful v2 IsSuperUser mirror (§12 OS4).
AUTHZ_TOKENS = ("get_authorized_", "user_has_", "_require", "is_superuser")

_ROUTE_VERBS = {"get", "post", "put", "patch", "delete"}


def _rel(path: Path) -> str:
    return path.relative_to(_REPO_ROOT).as_posix()


def _is_router_verb_attr(node: ast.AST) -> bool:
    """True for an attribute access ``router.<verb>`` (get/post/put/patch/delete)."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _ROUTE_VERBS
        and isinstance(node.value, ast.Name)
        and node.value.id == "router"
    )


def _is_router_decorator(dec: ast.AST) -> bool:
    """True for ``@router.<verb>(...)``."""
    return isinstance(dec, ast.Call) and _is_router_verb_attr(dec.func)


def _own_nodes(func: ast.FunctionDef):
    """
    Yield the descendant nodes of ``func``'s body WITHOUT descending into nested function/lambda
    definitions -- so a helper is credited only for authorization references in its *own* logic,
    never for tokens that live in a closure it merely encloses.
    """
    stack = list(func.body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            stack.append(child)


def _own_identifiers(func: ast.FunctionDef) -> set[str]:
    """All ``Name``/``Attribute`` identifiers used directly in ``func``'s own body."""
    idents: set[str] = set()
    for node in _own_nodes(func):
        if isinstance(node, ast.Name):
            idents.add(node.id)
        elif isinstance(node, ast.Attribute):
            idents.add(node.attr)
    return idents


def _own_call_targets(func: ast.FunctionDef) -> set[str]:
    """Names of same-module functions ``func`` calls directly (for one-level indirection)."""
    targets: set[str] = set()
    for node in _own_nodes(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            targets.add(node.func.id)
    return targets


def _has_authz_token(idents: set[str]) -> bool:
    return any(any(tok in ident for tok in AUTHZ_TOKENS) for ident in idents)


def _manually_registered_names(tree: ast.AST) -> set[str]:
    """
    Function names registered via ``router.<verb>(path, ...)(fn)`` (subresources.py registers its
    handlers manually so each gets a unique __name__ / operationId). The outer node is a Call whose
    ``func`` is itself the ``router.<verb>(...)`` Call; its positional Name args are the handlers.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Call)
            and _is_router_verb_attr(node.func.func)
        ):
            names.update(arg.id for arg in node.args if isinstance(arg, ast.Name))
    return names


def _route_operations(tree: ast.AST) -> list[ast.FunctionDef]:
    """Every function registered as a route operation (decorated OR manually registered)."""
    registered = _manually_registered_names(tree)
    ops: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if any(_is_router_decorator(dec) for dec in node.decorator_list) or node.name in registered:
            ops.append(node)
    return ops


def _authz_helper_names(tree: ast.AST) -> set[str]:
    """Same-module functions whose OWN body references an authorization primitive."""
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and _has_authz_token(_own_identifiers(node))
    }


class TestApiV3AuthzStatic(SimpleTestCase):

    """Source-scan tripwire: no raw manager access; every route operation is authz-wired."""

    def test_scanned_files_exist(self):
        """Guard the glob: the resource route modules must actually be found and scanned."""
        files = _scanned_files()
        rels = {_rel(f) for f in files}
        self.assertTrue(all(f.exists() for f in files), f"missing scanned file(s): {sorted(rels)}")
        # A representative subset must be present (catches a broken glob / moved module).
        for expected in (
            "dojo/finding/api_v3/routes.py",
            "dojo/location/api_v3/routes.py",
            "dojo/api_v3/import_routes.py",
            "dojo/api_v3/subresources.py",
        ):
            self.assertIn(expected, rels, f"{expected} not in the scan set -- fix _scanned_files()")

    def test_no_unjustified_objects_manager_access(self):
        """Rule A: every ``.objects.`` line must be in the audited allowlist (with a justification)."""
        failures: list[str] = []
        seen_allowlist_keys: set[tuple[str, str]] = set()
        for path in _scanned_files():
            rel = _rel(path)
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if ".objects." not in line:
                    continue
                pattern = self._objects_pattern(line)
                key = (rel, pattern)
                if key in OBJECTS_ALLOWLIST:
                    seen_allowlist_keys.add(key)
                    continue
                failures.append(
                    f"{rel}:{lineno}: direct model-manager access `{pattern}` -- reads must go "
                    f"through get_authorized_* (I8). If this is a genuine exception, add "
                    f"('{rel}', '{pattern}') to OBJECTS_ALLOWLIST with a one-line justification.",
                )
        self.assertFalse(failures, "unjustified .objects. access:\n" + "\n".join(failures))

        # Keep the allowlist honest: no entry may allow a pattern that no longer occurs.
        stale = set(OBJECTS_ALLOWLIST) - seen_allowlist_keys
        self.assertFalse(
            stale,
            f"stale OBJECTS_ALLOWLIST entr(y/ies) that match nothing anymore -- remove: {sorted(stale)}",
        )

    def test_every_file_references_an_authz_primitive(self):
        """Rule B(1): each scanned file references at least one authorization primitive."""
        failures: list[str] = []
        for path in _scanned_files():
            source = path.read_text(encoding="utf-8")
            if not any(tok in source for tok in AUTHZ_TOKENS):
                failures.append(f"{_rel(path)}: no authorization primitive {AUTHZ_TOKENS} anywhere in file")
        self.assertFalse(failures, "file with no authorization reference:\n" + "\n".join(failures))

    def test_every_route_operation_is_authz_wired(self):
        """Rule B(2): every route operation references an authz primitive directly or one helper deep."""
        failures: list[str] = []
        for path in _scanned_files():
            rel = _rel(path)
            tree = ast.parse(path.read_text(encoding="utf-8"))
            authz_helpers = _authz_helper_names(tree)
            operations = _route_operations(tree)
            # Sanity: the heuristic must find at least one route operation per file, otherwise a
            # broken detector would vacuously "pass" the whole file.
            self.assertTrue(
                operations,
                f"{rel}: no route operation detected -- the @router.<verb> / router.<verb>(...)(fn) "
                f"heuristic may be broken (or the file no longer defines routes).",
            )
            for op in operations:
                direct = _has_authz_token(_own_identifiers(op))
                indirect = bool(_own_call_targets(op) & authz_helpers)
                if not (direct or indirect):
                    failures.append(
                        f"{rel}::{op.name} (line {op.lineno}): route operation has no authorization "
                        f"reference in its body or in a same-module helper it calls -- it must flow "
                        f"through get_authorized_* / user_has_* / _require* / is_superuser (I8).",
                    )
        self.assertFalse(failures, "route operation missing an authorization check:\n" + "\n".join(failures))

    @staticmethod
    def _objects_pattern(line: str) -> str:
        """Extract the ``Model.objects.method`` token from a line (fallback: the stripped line)."""
        import re  # noqa: PLC0415 -- localized to this helper

        match = re.search(r"(\w+)\.objects\.(\w+)", line)
        return f"{match.group(1)}.objects.{match.group(2)}" if match else line.strip()
