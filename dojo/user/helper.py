from django.conf import settings
import logging
from django.core.exceptions import PermissionDenied
import functools
from django.shortcuts import get_object_or_404

logger = logging.getLogger(__name__)


def user_must_be_authorized(model, perm_type, arg, lookup="pk", view_func=None):
    # print('model: ', model)
    # print('arg: ', arg)
    # print('lookup: ', lookup)
    # print('view_func: ', view_func)

    """Decorator for view functions that ensures the user has permission on an object.

    It looks up the requested object in the user-restricted base queryset, checks
    for the object-level permission with given type and, if all went well, passes the
    retrieved object through to the view function. The object retrieved is passed
    as positional argument, directly after ``request``, the original lookup value
    (such as a primary key from URL) is removed from the arguments.

    This unifies (and simplifies) the typical ``get_object_or_404()`` + permission
    checking workflow, so that the view function doesn't have to deal with permissions
    and object retrival at all.

    :param model: The model to fetch objects of and do permission checking for
    :type  model: Model
    :param arg:
        Index of the function argument containing the value to look up in database
        (i.e. the object's primary key), not counting the first argument (``request``).
        If this is a keyword-argument rather than a positional one, specify its name
        as a string.
        ``None`` will disable object fetching entirely and only do model-level
        permission checking (usable for permission types like "add" that aren't
        related to a specific object).
    :type  arg: int, str
    :param lookup: Db lookup for selecting the requested object
    :type  lookup: str, optional
    :param view_func: The view function to wrap, not required for use as a decorator
    :type  view_func: callable, optional
    :raises Http404:
        if requested object isn't found
    :raises PermissionDenied: If object-/model-level permission check fails
    """

    if view_func is None:
        return functools.partial(user_must_be_authorized, model, perm_type, arg, lookup)

    @functools.wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        # print(f' Args: {args}')
        # print(f' Kwargs: {kwargs}')

        # Fetch object from database
        if isinstance(arg, int):
            # Lookup value came as a positional argument
            args = list(args)
            lookup_value = args.pop(arg)
        else:
            # Lookup value was passed as keyword argument
            lookup_value = kwargs.pop(arg)

        # object must exist
        obj = get_object_or_404(
            # model.objects.for_user(request), **{lookup: lookup_value}
            model.objects.filter(**{lookup: lookup_value})
        )

        is_authorized = user_is_authorized(request.user, perm_type, obj)
        if not is_authorized:
            logger.warn('User %s is not authorized to %s for %s', request.user, perm_type, obj)
            raise PermissionDenied()

        # print('user is authorized for: ', obj)
        # Django doesn't seem to easily support just passing on the original positional parameters
        # so we resort to explicitly putting lookup_value here (which is for example the 'fid' parameter)
        return view_func(request, lookup_value, *args, **kwargs)

    return _wrapped


def user_is_authorized(user, perm_type, obj):
    # print('help.user_is_authorized')
    # print('user: ', user)
    # print('perm_type', perm_type)
    # print('obj: ', obj)

    if perm_type not in ['view', 'change', 'delete']:
        logger.error('permtype %s not supported', perm_type)
        raise ValueError('permtype ' + perm_type + ' not supported')

    if user.is_staff:
        return True

    if perm_type == 'change' and not settings.AUTHORIZED_USERS_ALLOW_CHANGE:
        return user.is_staff or user.is_superuser

    if perm_type == 'delete' and not settings.AUTHORIZED_USERS_ALLOW_DELETE:
        return user.is_staff or user.is_superuser

    # at this point being in the authorized users lists means permission should be granted
    is_authorized = False
    from dojo.models import Finding, Test, Engagement, Product, Endpoint

    if isinstance(obj, Finding):
        is_authorized = user in obj.test.engagement.product.authorized_users.all()
    if isinstance(obj, Test):
        is_authorized = user in obj.engagement.product.authorized_users.all()
    if isinstance(obj, Engagement):
        is_authorized = user in obj.product.authorized_users.all()
    if isinstance(obj, Product):
        is_authorized = user in obj.authorized_users.all()
    if isinstance(obj, Endpoint):
        is_authorized = user in obj.product.authorized_users.all()

    return is_authorized
