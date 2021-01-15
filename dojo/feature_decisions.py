from django.conf import settings


def new_permissions_enabled():
    return settings.FEATURE_NEW_PERMISSIONS
