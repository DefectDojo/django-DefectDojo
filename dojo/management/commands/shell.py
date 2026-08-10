from importlib import import_module

from django.core.management.commands.shell import Command as ShellCommand
from django.utils.module_loading import import_string as import_dotted_path


class Command(ShellCommand):

    """
    DefectDojo override of Django's ``shell`` command.

    Django's shell auto-imports every model in ``INSTALLED_APPS`` by its
    ``"<module>.<name>"`` path. DefectDojo has models that exist on the app
    registry but are not importable by that path:

    * dynamically generated Tagulous tag models (``Tagulous_*_tags`` /
      ``Tagulous_*_inherited_tags``), and
    * auditlog proxy models (e.g. ``dojo.auditlog.services.*`` and the Pro
      ``*Proxy`` models).

    The stock command lists ~36 of these as "could not be automatically
    imported" on every launch, which reads like an error even though nothing
    is wrong. Drop the non-importable paths from the auto-import list so the
    banner is clean, without losing any auto-import that would actually have
    worked. The filter is generic (it tries the import and keeps what
    succeeds), so it covers both open-source and Pro models.
    """

    def get_auto_imports(self):
        paths = super().get_auto_imports()
        if not paths:
            return paths
        importable = []
        for path in paths:
            try:
                import_dotted_path(path) if "." in path else import_module(path)
            except ImportError:
                continue
            importable.append(path)
        return importable
