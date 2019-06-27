from django.conf import settings
from social_core.backends.azuread_tenant import AzureADTenantOAuth2
from social_core.backends.google import GoogleOAuth2


def social_uid(backend, details, response, *args, **kwargs):
    if settings.AZUREAD_TENANT_OAUTH2_ENABLED and isinstance(backend, AzureADTenantOAuth2):
        """Return user details from Azure AD account"""
        fullname, first_name, last_name, upn = (
            response.get('name', ''),
            response.get('given_name', ''),
            response.get('family_name', ''),
            response.get('upn'),
        )
        uid = backend.get_user_id(details, response)
        return {'username': upn,
                'email': upn,
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name,
                'uid': uid}
    elif settings.GOOGLE_OAUTH_ENABLED and isinstance(backend, GoogleOAuth2):
        """Return user details from Google account"""
        if 'sub' in response:
            google_uid = response['sub']
        elif 'email' in response:
            google_uid = response['email']
        else:
            google_uid = response['id']
        fullname, first_name, last_name, email = (
            response.get('fullname', ''),
            response.get('first_name', ''),
            response.get('last_name', ''),
            response.get('email'),
        )
        return {'username': email,
                'email': email,
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name,
                'uid': google_uid}
    else:
        uid = backend.get_user_id(details, response)
        # Used for most backends
        if uid:
            return {'uid': uid}
        # Until OKTA PR in social-core is merged
        # This modified way needs to work
        else:
            return {'uid': response.get('preferred_username')}


def modify_permissions(backend, uid, user=None, social=None, *args, **kwargs):
    if kwargs.get('is_new'):
        user.is_staff = True
