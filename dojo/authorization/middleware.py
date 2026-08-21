from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

from dojo.authorization.authorization import (
    user_has_configuration_permission,
    user_has_global_permission_or_403,
    user_has_permission_or_403,
)
from dojo.authorization.url_permissions import URL_PERMISSIONS


class AuthorizationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip API paths -- DRF has its own permission classes
        if request.path.startswith("/api/"):
            return

        resolver_match = request.resolver_match
        if resolver_match is None:
            return

        url_name = resolver_match.url_name
        checks = URL_PERMISSIONS.get(url_name)
        if not checks:
            return

        for check in checks:
            check_type = check[0]
            if check_type == "global":
                _, permission = check
                user_has_global_permission_or_403(request.user, permission)
            elif check_type == "config":
                _, permission = check
                if not user_has_configuration_permission(request.user, permission):
                    raise PermissionDenied
            elif check_type == "object":
                _, model, permission, arg_name = check
                lookup_value = view_kwargs.get(arg_name)
                if lookup_value is None:
                    # The URL pattern and the URL_PERMISSIONS entry have drifted
                    # apart on the kwarg name. Treat as a configuration error
                    # and deny rather than silently allowing the request.
                    raise PermissionDenied
                obj = get_object_or_404(model, pk=lookup_value)
                user_has_permission_or_403(request.user, obj, permission)

        return
