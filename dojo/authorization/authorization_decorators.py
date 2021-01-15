import functools
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from dojo.feature_decisions import new_permissions_enabled
from dojo.authorization.authorization import user_has_permission


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
        obj = get_object_or_404(
            # model.objects.for_user(request), **{lookup: lookup_value}
            model.objects.filter(**{lookup: lookup_value})
        )

        if new_permissions_enabled():
            if not user_has_permission(request.user, obj, permission) and not request.user.is_superuser:
                raise PermissionDenied()
        else:
            if not request.user.is_staff:
                raise PermissionDenied()

        return func(request, *args, **kwargs)

    return _wrapped
