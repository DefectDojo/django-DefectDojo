from django.conf import settings # import the settings file


def globalize_oauth_vars(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {'GOOGLE_ENABLED': settings.GOOGLE_OAUTH_ENABLED,
            'OKTA_ENABLED': settings.OKTA_OAUTH_ENABLED}