from dojo.v3_migration.utils import get_migration_urlconf


class V3MigrationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def get_urlconf(self):
        return get_migration_urlconf()

    def __call__(self, request):
        request.urlconf = self.get_urlconf()
        return self.get_response(request)
