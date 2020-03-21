import collections

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


class BuilderRegistry(collections.OrderedDict):
    """
    Holds instances of all builder classes registered using the register() method,
    indexed by their internal code.
    """

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            raise KeyError("No builder registered with code {!r}".format(key))

    def __setitem__(self, key, value):
        raise NotImplementedError(
            "Use BuilderRegistry.register() to register new builder instances"
        )

    def register(self, spec):
        """Instantiates the specified builder class and registers it in the registry.

        A specification to pass to this function could originate from the
        REPORTNG_BUILDERS list in settings.py.
        """
        if isinstance(spec, dict):
            spec = spec.copy()
        else:
            spec = {"class": spec}

        builder_class = spec.pop("class")
        if isinstance(builder_class, str):
            builder_class = import_string(builder_class)

        builder = builder_class(spec)
        if builder.code in self:
            raise ImproperlyConfigured(
                "Can't register two report builders with same code %r: %r and %r (new)"
                % (builder.code, self[builder.code], builder)
            )
        super().__setitem__(builder.code, builder)


# The default builder registry
BUILDER_REGISTRY = BuilderRegistry()
