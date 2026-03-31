from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.http import urlencode


def get_sso_auto_redirect(request):
    """Return an HttpResponseRedirect to the SSO provider if auto-redirect conditions are met, or None."""
    if not settings.SHOW_LOGIN_FORM and settings.SOCIAL_LOGIN_AUTO_REDIRECT and sum([
        settings.GOOGLE_OAUTH_ENABLED,
        settings.OKTA_OAUTH_ENABLED,
        settings.AZUREAD_TENANT_OAUTH2_ENABLED,
        settings.GITLAB_OAUTH2_ENABLED,
        settings.AUTH0_OAUTH2_ENABLED,
        settings.KEYCLOAK_OAUTH2_ENABLED,
        settings.GITHUB_ENTERPRISE_OAUTH2_ENABLED,
        settings.OIDC_AUTH_ENABLED,
        settings.SAML2_ENABLED,
    ]) == 1 and "force_login_form" not in request.GET:
        if settings.GOOGLE_OAUTH_ENABLED:
            social_auth = "google-oauth2"
        elif settings.OKTA_OAUTH_ENABLED:
            social_auth = "okta-oauth2"
        elif settings.AZUREAD_TENANT_OAUTH2_ENABLED:
            social_auth = "azuread-tenant-oauth2"
        elif settings.GITLAB_OAUTH2_ENABLED:
            social_auth = "gitlab"
        elif settings.KEYCLOAK_OAUTH2_ENABLED:
            social_auth = "keycloak"
        elif settings.OIDC_AUTH_ENABLED:
            social_auth = "oidc"
        elif settings.AUTH0_OAUTH2_ENABLED:
            social_auth = "auth0"
        elif settings.GITHUB_ENTERPRISE_OAUTH2_ENABLED:
            social_auth = "github-enterprise"
        else:
            return HttpResponseRedirect("/saml2/login")
        try:
            return HttpResponseRedirect("{}?{}".format(reverse("social:begin", args=[social_auth]),
                                                   urlencode({"next": request.GET.get("next", "/dashboard")})))
        except Exception:
            return HttpResponseRedirect(reverse("social:begin", args=[social_auth]))
    return None
