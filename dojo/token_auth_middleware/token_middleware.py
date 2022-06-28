from rest_framework.authentication import TokenAuthentication

# https://gitlab.com/cki-project/datawarehouse/-/issues/108
# https://github.com/encode/django-rest-framework/issues/760#issuecomment-391127616
# https://github.com/encode/django-rest-framework/blob/master/rest_framework/authentication.py#L177


class TokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def _add_user_from_token(self, request):
        token_auth = TokenAuthentication().authenticate(request)
        if token_auth:
            request.user = token_auth[0]

    def __call__(self, request):
        if (
            (request.user is None or request.user.id is None) and
            request.META.get('HTTP_AUTHORIZATION')
        ):
            self._add_user_from_token(request)

        return self.get_response(request)
