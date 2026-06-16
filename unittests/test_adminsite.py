import django.apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from .dojo_test_case import DojoTestCase


class AdminSite(DojoTestCase):

    def test_is_model_defined(self):
        for subclass in django.apps.apps.get_models():
            if subclass._meta.proxy:
                continue
            if subclass.__module__ == "dojo.models":
                # Skip pghistory Event models - they're audit trail models not meant for admin
                if subclass.__name__.endswith("Event"):
                    continue
                if not ((subclass.__name__[:9] == "Tagulous_") and (subclass.__name__[-5:] == "_tags")):
                    with self.subTest(type="base", subclass=subclass):
                        self.assertIn(subclass, admin.site._registry.keys(), f"{subclass} is not registered in 'admin.site' in models.py")
                else:
                    with self.subTest(type="tag", subclass=subclass):
                        self.assertIn(subclass, admin.site._registry.keys(), f"{subclass} is not registered in 'tagulous.admin' in models.py")


class AdminAccessGate(DojoTestCase):

    """
    is_staff is a near-superuser bypass under the legacy OS auth model, so
    /admin/ must require is_superuser. Django's default UserAdmin change
    form would otherwise let any is_staff user with auth.change_user tick
    is_superuser on themselves. Tested at the gate-function level so the
    assertions hold regardless of whether DD_DJANGO_ADMIN_ENABLED mounts
    the admin URLConf in the current environment.
    """

    @staticmethod
    def _request_for(user):
        req = HttpRequest()
        req.user = user
        return req

    def test_staff_non_superuser_denied(self):
        User = get_user_model()
        password = "testTEST1234!@#$"
        staff = User.objects.create_user(
            username="staff-no-root", password=password, is_staff=True,
        )
        self.assertFalse(admin.site.has_permission(self._request_for(staff)))

    def test_non_staff_non_superuser_denied(self):
        User = get_user_model()
        password = "testTEST1234!@#$"
        plain = User.objects.create_user(username="plain-user", password=password)
        self.assertFalse(admin.site.has_permission(self._request_for(plain)))

    def test_anonymous_denied(self):
        self.assertFalse(admin.site.has_permission(self._request_for(AnonymousUser())))

    def test_inactive_superuser_denied(self):
        User = get_user_model()
        password = "testTEST1234!@#$"
        root = User.objects.create_superuser(
            username="inactive-root", email="i@example.com", password=password,
        )
        root.is_active = False
        root.save(update_fields=["is_active"])
        self.assertFalse(admin.site.has_permission(self._request_for(root)))

    def test_active_superuser_allowed(self):
        User = get_user_model()
        password = "testTEST1234!@#$"
        root = User.objects.create_superuser(
            username="root-test", email="r@example.com", password=password,
        )
        self.assertTrue(admin.site.has_permission(self._request_for(root)))
