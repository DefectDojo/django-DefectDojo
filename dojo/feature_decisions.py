from django.conf import settings


def new_authorization_enabled():
    return settings.FEATURE_NEW_AUTHORIZATION
