import django.apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.urls import reverse

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
    is_superuser on themselves.
    """

    def test_staff_non_superuser_blocked_from_admin(self):
        User = get_user_model()
        staff = User.objects.create_user(
            username="staff-no-root", password="x", is_staff=True,
        )
        self.client.force_login(staff)

        for url in (
            reverse("admin:index"),
            reverse("admin:auth_user_changelist"),
            reverse("admin:auth_user_change", args=[staff.id]),
        ):
            with self.subTest(url=url):
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 302, url)
                self.assertIn("/admin/login/", resp["Location"], url)

    def test_superuser_can_reach_admin(self):
        User = get_user_model()
        root = User.objects.create_superuser(
            username="root-test", email="r@example.com", password="x",
        )
        self.client.force_login(root)

        self.assertEqual(self.client.get(reverse("admin:index")).status_code, 200)
        self.assertEqual(
            self.client.get(reverse("admin:auth_user_changelist")).status_code,
            200,
        )
