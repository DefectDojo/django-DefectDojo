"""
Regression tests: every viewset module split out of ``dojo.api_v2.views`` imports cleanly on its own.

The split-out modules (``dojo.jira.api.views`` and the rest) import their base classes from
``dojo.api_v2.views``. While ``dojo.api_v2.views`` also re-imported them at module level for backward
compatibility, importing a split-out module first failed: it started loading, pulled in
``dojo.api_v2.views``, which asked the half-initialized module for names it had not defined yet
(``ImportError: cannot import name 'JiraInstanceViewSet' from partially initialized module``). It only
worked when something else had imported ``dojo.api_v2.views`` first. The backward-compatible names are
now resolved lazily through the module's ``__getattr__``.

Each module is imported in a fresh interpreter, because any earlier import in this test process
would hide the cycle.
"""

import importlib
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from django.test import SimpleTestCase

import dojo
from dojo.api_v2 import views as api_v2_views

REPO_ROOT = Path(dojo.__file__).resolve().parent.parent

# Exit code 3: django.setup() already imported the module, so this run cannot tell whether
# importing it first works. Fail loudly rather than pass without testing anything.
IMPORT_FIRST = """
import importlib
import sys

import django

django.setup()
name = sys.argv[1]
if name in sys.modules:
    print(f"{name} was already imported by django.setup()")
    sys.exit(3)
importlib.import_module(name)
"""


def _split_out_viewset_modules():
    # Found on disk rather than read from dojo.api_v2.views, so a module that is missing from
    # its lazy-export map (or one added later) is still checked.
    return sorted(
        ".".join(path.relative_to(REPO_ROOT).with_suffix("").parts)
        for path in REPO_ROOT.joinpath("dojo").glob("**/api/views.py")
    )


def _import_first(module_name):
    return subprocess.run(
        [sys.executable, "-c", IMPORT_FIRST, module_name],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=600,
        check=False,
    )


class ApiV2ViewsImportCycleTest(SimpleTestCase):
    def test_each_split_out_viewset_module_imports_first_in_a_fresh_interpreter(self):
        modules = _split_out_viewset_modules()
        self.assertIn("dojo.jira.api.views", modules)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = dict(zip(modules, pool.map(_import_first, modules), strict=True))
        for module_name, result in results.items():
            with self.subTest(module=module_name):
                self.assertEqual(0, result.returncode, f"importing {module_name} first failed:\n{result.stdout}{result.stderr[-3000:]}")

    def test_the_jira_and_note_viewsets_are_lazy_exports(self):
        for name in ("JiraInstanceViewSet", "JiraIssuesViewSet", "JiraProjectViewSet", "NoteTypeViewSet", "NotesViewSet"):
            with self.subTest(name=name):
                self.assertIn(name, api_v2_views._LAZY_VIEWSET_EXPORTS)
                self.assertNotIn(name, vars(api_v2_views))

    def test_backward_compatible_names_still_resolve_from_api_v2_views(self):
        for name, module_name in api_v2_views._LAZY_VIEWSET_EXPORTS.items():
            with self.subTest(name=name):
                self.assertIs(getattr(importlib.import_module(module_name), name), getattr(api_v2_views, name))

    def test_from_import_of_a_moved_viewset_still_works(self):
        from dojo.api_v2.views import JiraInstanceViewSet, NotesViewSet, NoteTypeViewSet  # noqa: PLC0415
        from dojo.jira.api.views import JiraInstanceViewSet as MovedJiraInstanceViewSet  # noqa: PLC0415
        from dojo.note_type.api.views import NoteTypeViewSet as MovedNoteTypeViewSet  # noqa: PLC0415
        from dojo.notes.api.views import NotesViewSet as MovedNotesViewSet  # noqa: PLC0415

        self.assertIs(MovedJiraInstanceViewSet, JiraInstanceViewSet)
        self.assertIs(MovedNoteTypeViewSet, NoteTypeViewSet)
        self.assertIs(MovedNotesViewSet, NotesViewSet)

    def test_dir_lists_every_lazy_export(self):
        names = dir(api_v2_views)
        for name in api_v2_views._LAZY_VIEWSET_EXPORTS:
            with self.subTest(name=name):
                self.assertIn(name, names)
        self.assertIn("DojoModelViewSet", names)

    def test_an_unknown_name_still_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            api_v2_views.NoSuchViewSet  # noqa: B018
