"""
Template loader that selects between the classic and Tailwind UI trees per request.

Two parallel template directories are maintained on this branch:

- ``dojo/templates/`` — Tailwind v4 + Alpine.js / htmx UI (the new opt-in UI)
- ``dojo/templates_classic/`` — Bootstrap 3 + SB Admin 2 UI (default)

`UIPreferenceLoader` resolves a template name from one tree first, falling back
to the other. The order is decided per request based on
`request.user.usercontactinfo.ui_use_tailwind`. Anonymous users (login pages,
error pages) and authenticated users who opted in get the Tailwind tree first.
Everyone else gets the classic tree first.

The current request is read via `crum.get_current_request()` — `crum`'s
`CurrentRequestUserMiddleware` is already wired into the middleware chain in
`dojo/settings/settings.dist.py`.
"""

from crum import get_current_request
from django.template import TemplateDoesNotExist
from django.template.loaders.base import Loader as BaseLoader
from django.template.loaders.cached import Loader as CachedLoader
from django.template.loaders.filesystem import Loader as FilesystemLoader

_FILESYSTEM_LOADER_PATH = "django.template.loaders.filesystem.Loader"


class UIPreferenceLoader(BaseLoader):

    def __init__(self, engine, tailwind_dir, classic_dir):
        super().__init__(engine)
        # Inner loaders maintain their own template caches when not in debug
        # mode. Caching at this outer layer would be incorrect because the
        # cache key would not include the per-user UI preference.
        if engine.debug:
            self._tailwind_loader = FilesystemLoader(engine, [tailwind_dir])
            self._classic_loader = FilesystemLoader(engine, [classic_dir])
        else:
            # ``CachedLoader`` resolves each entry in its loader list via
            # ``engine.find_template_loader``, which only accepts ``str`` /
            # ``(str, *args)`` configurations — passing a ``Loader`` instance
            # raises ``ImproperlyConfigured: Invalid value in template
            # loaders configuration``. Express the inner filesystem loader
            # as a ``(loader_path, [dirs])`` tuple so ``find_template_loader``
            # can instantiate it correctly.
            self._tailwind_loader = CachedLoader(
                engine, [(_FILESYSTEM_LOADER_PATH, [tailwind_dir])],
            )
            self._classic_loader = CachedLoader(
                engine, [(_FILESYSTEM_LOADER_PATH, [classic_dir])],
            )

    def _ordered_loaders(self):
        request = get_current_request()
        if request is None:
            return (self._tailwind_loader, self._classic_loader)
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return (self._tailwind_loader, self._classic_loader)
        contact = getattr(user, "usercontactinfo", None)
        if contact is not None and getattr(contact, "ui_use_tailwind", False):
            return (self._tailwind_loader, self._classic_loader)
        return (self._classic_loader, self._tailwind_loader)

    def get_template(self, template_name, skip=None):
        tried = []
        for loader in self._ordered_loaders():
            try:
                return loader.get_template(template_name, skip=skip)
            except TemplateDoesNotExist as exc:
                tried.extend(exc.tried)
        raise TemplateDoesNotExist(template_name, tried=tried)

    def get_template_sources(self, template_name):
        for loader in self._ordered_loaders():
            yield from loader.get_template_sources(template_name)

    def reset(self):
        for loader in (self._tailwind_loader, self._classic_loader):
            if hasattr(loader, "reset"):
                loader.reset()
