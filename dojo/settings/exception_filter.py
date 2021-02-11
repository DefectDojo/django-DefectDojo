from django.views.debug import SafeExceptionReporterFilter


class CustomExceptionReporterFilter(SafeExceptionReporterFilter):
    def is_active(self, request):
        # always activate for sensitive stuff we want to hide
        # even when DEBUG = True
        return True
