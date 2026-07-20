from importlib import import_module

from django.core.management.commands.shell import Command as BaseShellCommand
from django.utils.module_loading import import_string

from dojo.management.commands.shell import Command

from .dojo_test_case import DojoTestCase


class TestShellAutoImportFilter(DojoTestCase):

    """
    The overridden ``shell`` command must drop non-importable auto-imports.

    Django's stock shell lists dynamically generated Tagulous tag models and
    auditlog proxy models as "could not be automatically imported" on every
    launch. The override filters the auto-import list down to paths that
    actually import, so the banner is clean without losing real auto-imports.
    """

    def _resolve(self, path):
        return import_string(path) if "." in path else import_module(path)

    def test_all_returned_paths_are_importable(self):
        paths = Command().get_auto_imports()
        self.assertTrue(paths, "expected a non-empty auto-import list")
        for path in paths:
            try:
                self._resolve(path)
            except ImportError:
                self.fail(f"get_auto_imports() returned a non-importable path: {path}")

    def test_real_models_are_kept(self):
        self.assertIn("dojo.finding.models.Finding", Command().get_auto_imports())

    def test_only_non_importable_paths_are_dropped(self):
        base_paths = BaseShellCommand().get_auto_imports()
        kept = set(Command().get_auto_imports())
        dropped = [path for path in base_paths if path not in kept]
        # The override must actually remove something (the environment has
        # dynamically generated / proxy models that Django cannot import).
        self.assertTrue(dropped, "expected the override to drop at least one non-importable path")
        # Everything it drops must genuinely be non-importable.
        for path in dropped:
            with self.assertRaises(ImportError, msg=f"{path} was dropped but is importable"):
                self._resolve(path)
