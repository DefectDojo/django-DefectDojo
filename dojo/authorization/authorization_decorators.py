import functools
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from dojo.authorization.authorization import user_has_permission
from dojo.user.helper import user_is_authorized as legacy_check


def user_is_authorized(model, permission, arg, lookup="pk", func=None):
    """Decorator for functions that ensures the user has permission on an object.
    """

    if func is None:
        return functools.partial(user_is_authorized, model, permission, arg, lookup)

    @functools.wraps(func)
    def _wrapped(request, *args, **kwargs):
        # Fetch object from database
        if isinstance(arg, int):
            # Lookup value came as a positional argument
            args = list(args)
            lookup_value = args[arg]
        else:
            # Lookup value was passed as keyword argument
            lookup_value = kwargs.get(arg)

        # object must exist
        obj = get_object_or_404(model.objects.filter(**{lookup: lookup_value}))

        if settings.FEATURE_NEW_AUTHORIZATION:
            if not user_has_permission(request.user, obj, permission) and not request.user.is_superuser:
                raise PermissionDenied()
        else:
            if permission.name.endswith("View"):
                if not legacy_check(request.user, 'view', obj):
                    raise PermissionDenied()
            elif not request.user.is_staff:
                raise PermissionDenied()

        return func(request, *args, **kwargs)

    return _wrapped
