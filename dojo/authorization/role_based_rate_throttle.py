import logging
from rest_framework.throttling import UserRateThrottle
from dojo.models import GeneralSettings
logger = logging.getLogger(__name__)


class RoleBasedRateThrottle(UserRateThrottle):
    def allow_request(self, request, view):
        self.rate = GeneralSettings.get_value(
            "RATE_LIMIT_WEB_USERS",
            "100/minute")
        if request.user.is_authenticated:
            if request.user.is_superuser:
                self.rate = GeneralSettings.get_value(
                    "RATE_LIMIT_SUPERUSERS",
                    "400/second")
            elif hasattr(request.user, 'global_role') and request.user.global_role:
                if request.user.global_role.role.name == "API_Importer":
                    self.rate = GeneralSettings.get_value(
                        "RATE_LIMIT_API_IMPORTERS",
                        "400/second")
                elif request.user.global_role.role.name == "Maintainer":
                    self.rate = GeneralSettings.get_value(
                        "RATE_LIMIT_API_MAINTAINERS",
                        "400/second")
            self.num_requests, self.duration = self.parse_rate(self.rate)
            self.key = self.get_cache_key(request, view)
            if self.key is None:
                return True

            self.history = self.cache.get(self.key, [])
            self.now = self.timer()
            self.history = [timestamp for timestamp in self.history if timestamp > self.now - self.duration]

            if len(self.history) >= self.num_requests:
                logger.warning(
                    f"RATE LIMIT: exceeded for user {request.user.username}" )
                return self.throttle_failure()

            return self.throttle_success()
        return True