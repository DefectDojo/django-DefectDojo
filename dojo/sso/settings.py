from pathlib import Path

SSO_ENV_SCHEMA = {
    "DD_SOCIAL_AUTH_CREATE_USER": (bool, True),
    "DD_SOCIAL_AUTH_CREATE_USER_MAPPING": (str, "username"),
    "DD_SOCIAL_AUTH_REDIRECT_IS_HTTPS": (bool, False),
    "DD_SOCIAL_AUTH_TRAILING_SLASH": (bool, True),
    "DD_SOCIAL_AUTH_OIDC_AUTH_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_ID_KEY": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_KEY": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_USERNAME_KEY": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_WHITELISTED_DOMAINS": (list, []),
    "DD_SOCIAL_AUTH_OIDC_JWT_ALGORITHMS": (list, ["RS256", "HS256"]),
    "DD_SOCIAL_AUTH_OIDC_ID_TOKEN_ISSUER": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_ACCESS_TOKEN_URL": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_AUTHORIZATION_URL": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_USERINFO_URL": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_JWKS_URI": (str, ""),
    "DD_SOCIAL_AUTH_OIDC_LOGIN_BUTTON_TEXT": (str, "Login with OIDC"),
    "DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_AUTH0_KEY": (str, ""),
    "DD_SOCIAL_AUTH_AUTH0_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_AUTH0_DOMAIN": (str, ""),
    "DD_SOCIAL_AUTH_AUTH0_SCOPE": (list, ["openid", "profile", "email"]),
    "DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY": (str, ""),
    "DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS": (list, [""]),
    "DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS": (list, [""]),
    "DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY": (str, ""),
    "DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL": (str, "https://{your-org-url}/oauth2"),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY": (str, ""),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID": (str, ""),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE": (str, "https://graph.microsoft.com/"),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS": (bool, False),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER": (str, ""),
    "DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS": (bool, True),
    "DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT": (bool, False),
    "DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_TAGS": (bool, False),
    "DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_URL": (bool, False),
    "DD_SOCIAL_AUTH_GITLAB_PROJECT_MIN_ACCESS_LEVEL": (int, 20),
    "DD_SOCIAL_AUTH_GITLAB_KEY": (str, ""),
    "DD_SOCIAL_AUTH_GITLAB_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_GITLAB_API_URL": (str, "https://gitlab.com"),
    "DD_SOCIAL_AUTH_GITLAB_SCOPE": (list, ["read_user", "openid", "read_api", "read_repository"]),
    "DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_KEYCLOAK_KEY": (str, ""),
    "DD_SOCIAL_AUTH_KEYCLOAK_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY": (str, ""),
    "DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL": (str, ""),
    "DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL": (str, ""),
    "DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT": (str, "Login with Keycloak"),
    "DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED": (bool, False),
    "DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL": (str, ""),
    "DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL": (str, ""),
    "DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY": (str, ""),
    "DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET": (str, ""),
    "DD_SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL": (bool, True),
    "DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_REQUEST_EXCEPTION": (str, "Please use the standard login below."),
    "DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_CANCELED": (str, "Social login was canceled. Please try again or use the standard login."),
    "DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FAILED": (str, "Social login failed. Please try again or use the standard login."),
    "DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FORBIDDEN": (str, "You are not authorized to log in via this method. Please contact support or use the standard login."),
    "DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_NONE_TYPE": (str, "An unexpected error occurred during social login. Please use the standard login."),
    "DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_TOKEN_ERROR": (str, "Social login failed due to an invalid or expired token. Please try again or use the standard login."),
    "DD_SAML2_ENABLED": (bool, False),
    "DD_SAML2_AUTHENTICATION_BACKENDS": (str, "djangosaml2.backends.Saml2Backend"),
    "DD_SAML2_FORCE_AUTH": (bool, True),
    "DD_SAML2_LOGIN_BUTTON_TEXT": (str, "Login with SAML"),
    "DD_SAML2_LOGOUT_URL": (str, ""),
    "DD_SAML2_METADATA_AUTO_CONF_URL": (str, ""),
    "DD_SAML2_METADATA_LOCAL_FILE_PATH": (str, ""),
    "DD_SAML2_ENTITY_ID": (str, ""),
    "DD_SAML2_CREATE_USER": (bool, False),
    "DD_SAML2_ATTRIBUTES_MAP": (dict, {
        "Email": "email",
        "UserName": "username",
        "Firstname": "first_name",
        "Lastname": "last_name",
    }),
    "DD_SAML2_ALLOW_UNKNOWN_ATTRIBUTE": (bool, False),
    "DD_AUTH_REMOTEUSER_ENABLED": (bool, False),
    "DD_AUTH_REMOTEUSER_USERNAME_HEADER": (str, "REMOTE_USER"),
    "DD_AUTH_REMOTEUSER_EMAIL_HEADER": (str, ""),
    "DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER": (str, ""),
    "DD_AUTH_REMOTEUSER_LASTNAME_HEADER": (str, ""),
    "DD_AUTH_REMOTEUSER_GROUPS_HEADER": (str, ""),
    "DD_AUTH_REMOTEUSER_GROUPS_CLEANUP": (bool, True),
    "DD_AUTH_REMOTEUSER_TRUSTED_PROXY": (list, ["127.0.0.1/32"]),
    "DD_AUTH_REMOTEUSER_LOGIN_ONLY": (bool, False),
    "DD_AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER": (bool, False),
}


def _saml2_attrib_map_format(din):
    dout = {}
    for i in din:
        dout[i] = (din[i],)
    return dout


def apply_sso_settings(env, globs):
    """Apply all SSO-related settings. Called from settings.dist.py inside a try/except ImportError block."""
    from netaddr import IPNetwork, IPSet  # noqa: PLC0415

    SITE_URL = globs["SITE_URL"]
    URL_PREFIX = globs.get("URL_PREFIX", "")

    # --------------------------------------------------------------------------
    # AUTHENTICATION_BACKENDS
    # --------------------------------------------------------------------------
    globs["AUTHENTICATION_BACKENDS"] = (
        "social_core.backends.open_id_connect.OpenIdConnectAuth",
        "social_core.backends.auth0.Auth0OAuth2",
        "social_core.backends.google.GoogleOAuth2",
        "social_core.backends.okta.OktaOAuth2",
        "social_core.backends.azuread_tenant.AzureADTenantOAuth2",
        "social_core.backends.gitlab.GitLabOAuth2",
        "social_core.backends.keycloak.KeycloakOAuth2",
        "social_core.backends.github_enterprise.GithubEnterpriseOAuth2",
        "dojo.sso.remote_user.RemoteUserBackend",
        "django.contrib.auth.backends.RemoteUserBackend",
        "django.contrib.auth.backends.ModelBackend",
    )

    # --------------------------------------------------------------------------
    # SOCIAL_AUTH_PIPELINE
    # --------------------------------------------------------------------------
    globs["SOCIAL_AUTH_PIPELINE"] = (
        "social_core.pipeline.social_auth.social_details",
        "dojo.sso.pipeline.social_uid",
        "social_core.pipeline.social_auth.auth_allowed",
        "social_core.pipeline.social_auth.social_user",
        "social_core.pipeline.user.get_username",
        "social_core.pipeline.social_auth.associate_by_email",
        "dojo.sso.pipeline.create_user",
        "dojo.sso.pipeline.modify_permissions",
        "social_core.pipeline.social_auth.associate_user",
        "social_core.pipeline.social_auth.load_extra_data",
        "social_core.pipeline.user.user_details",
        "dojo.sso.pipeline.update_azure_groups",
        "dojo.sso.pipeline.update_product_access",
    )

    # --------------------------------------------------------------------------
    # SOCIAL AUTH GENERAL
    # --------------------------------------------------------------------------
    globs["SOCIAL_AUTH_REDIRECT_IS_HTTPS"] = env("DD_SOCIAL_AUTH_REDIRECT_IS_HTTPS")
    globs["SOCIAL_AUTH_CREATE_USER"] = env("DD_SOCIAL_AUTH_CREATE_USER")
    globs["SOCIAL_AUTH_CREATE_USER_MAPPING"] = env("DD_SOCIAL_AUTH_CREATE_USER_MAPPING")

    globs["SOCIAL_AUTH_STRATEGY"] = "social_django.strategy.DjangoStrategy"
    globs["SOCIAL_AUTH_STORAGE"] = "social_django.models.DjangoStorage"
    globs["SOCIAL_AUTH_ADMIN_USER_SEARCH_FIELDS"] = ["username", "first_name", "last_name", "email"]
    globs["SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL"] = env("DD_SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL")

    # --------------------------------------------------------------------------
    # GOOGLE OAUTH2
    # --------------------------------------------------------------------------
    globs["GOOGLE_OAUTH_ENABLED"] = env("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED")
    globs["SOCIAL_AUTH_GOOGLE_OAUTH2_KEY"] = env("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY")
    globs["SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET"] = env("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET")
    globs["SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS"] = tuple(env.list("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS", default=[""]))
    globs["SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS"] = tuple(env.list("DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS", default=[""]))
    globs["SOCIAL_AUTH_LOGIN_ERROR_URL"] = "/login"
    globs["SOCIAL_AUTH_BACKEND_ERROR_URL"] = "/login"

    # --------------------------------------------------------------------------
    # OKTA OAUTH2
    # --------------------------------------------------------------------------
    globs["OKTA_OAUTH_ENABLED"] = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED")
    globs["SOCIAL_AUTH_OKTA_OAUTH2_KEY"] = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY")
    globs["SOCIAL_AUTH_OKTA_OAUTH2_SECRET"] = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET")
    globs["SOCIAL_AUTH_OKTA_OAUTH2_API_URL"] = env("DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL")

    # --------------------------------------------------------------------------
    # AZURE AD TENANT OAUTH2
    # --------------------------------------------------------------------------
    globs["AZUREAD_TENANT_OAUTH2_ENABLED"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED")
    globs["SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY")
    globs["SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET")
    globs["SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID")
    globs["SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE")
    globs["AZUREAD_TENANT_OAUTH2_GET_GROUPS"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS")
    globs["AZUREAD_TENANT_OAUTH2_GROUPS_FILTER"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER")
    globs["AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS"] = env("DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS")

    # --------------------------------------------------------------------------
    # GITLAB OAUTH2
    # --------------------------------------------------------------------------
    globs["GITLAB_OAUTH2_ENABLED"] = env("DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED")
    globs["GITLAB_PROJECT_AUTO_IMPORT"] = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT")
    globs["GITLAB_PROJECT_IMPORT_TAGS"] = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_TAGS")
    globs["GITLAB_PROJECT_IMPORT_URL"] = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_IMPORT_URL")
    globs["GITLAB_PROJECT_MIN_ACCESS_LEVEL"] = env("DD_SOCIAL_AUTH_GITLAB_PROJECT_MIN_ACCESS_LEVEL")
    globs["SOCIAL_AUTH_GITLAB_KEY"] = env("DD_SOCIAL_AUTH_GITLAB_KEY")
    globs["SOCIAL_AUTH_GITLAB_SECRET"] = env("DD_SOCIAL_AUTH_GITLAB_SECRET")
    globs["SOCIAL_AUTH_GITLAB_API_URL"] = env("DD_SOCIAL_AUTH_GITLAB_API_URL")
    globs["SOCIAL_AUTH_GITLAB_SCOPE"] = env("DD_SOCIAL_AUTH_GITLAB_SCOPE")

    # Add required scope if auto import is enabled
    if globs["GITLAB_PROJECT_AUTO_IMPORT"]:
        globs["SOCIAL_AUTH_GITLAB_SCOPE"] += ["read_repository"]

    # --------------------------------------------------------------------------
    # OIDC
    # --------------------------------------------------------------------------
    globs["OIDC_AUTH_ENABLED"] = env("DD_SOCIAL_AUTH_OIDC_AUTH_ENABLED")
    globs["SOCIAL_AUTH_OIDC_OIDC_ENDPOINT"] = env("DD_SOCIAL_AUTH_OIDC_OIDC_ENDPOINT")
    globs["SOCIAL_AUTH_OIDC_KEY"] = env("DD_SOCIAL_AUTH_OIDC_KEY")
    globs["SOCIAL_AUTH_OIDC_SECRET"] = env("DD_SOCIAL_AUTH_OIDC_SECRET")
    # Optional OIDC settings
    if value := env("DD_LOGIN_REDIRECT_URL"):
        globs["SOCIAL_AUTH_LOGIN_REDIRECT_URL"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_ID_KEY"):
        globs["SOCIAL_AUTH_OIDC_ID_KEY"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_USERNAME_KEY"):
        globs["SOCIAL_AUTH_OIDC_USERNAME_KEY"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_WHITELISTED_DOMAINS"):
        globs["SOCIAL_AUTH_OIDC_WHITELISTED_DOMAINS"] = env("DD_SOCIAL_AUTH_OIDC_WHITELISTED_DOMAINS")
    if value := env("DD_SOCIAL_AUTH_OIDC_JWT_ALGORITHMS"):
        globs["SOCIAL_AUTH_OIDC_JWT_ALGORITHMS"] = env("DD_SOCIAL_AUTH_OIDC_JWT_ALGORITHMS")
    if value := env("DD_SOCIAL_AUTH_OIDC_ID_TOKEN_ISSUER"):
        globs["SOCIAL_AUTH_OIDC_ID_TOKEN_ISSUER"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_ACCESS_TOKEN_URL"):
        globs["SOCIAL_AUTH_OIDC_ACCESS_TOKEN_URL"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_AUTHORIZATION_URL"):
        globs["SOCIAL_AUTH_OIDC_AUTHORIZATION_URL"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_USERINFO_URL"):
        globs["SOCIAL_AUTH_OIDC_USERINFO_URL"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_JWKS_URI"):
        globs["SOCIAL_AUTH_OIDC_JWKS_URI"] = value
    if value := env("DD_SOCIAL_AUTH_OIDC_LOGIN_BUTTON_TEXT"):
        globs["SOCIAL_AUTH_OIDC_LOGIN_BUTTON_TEXT"] = value

    # --------------------------------------------------------------------------
    # SOCIAL AUTH EXCEPTION MESSAGES
    # --------------------------------------------------------------------------
    globs["SOCIAL_AUTH_EXCEPTION_MESSAGE_REQUEST_EXCEPTION"] = env("DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_REQUEST_EXCEPTION")
    globs["SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_CANCELED"] = env("DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_CANCELED")
    globs["SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FAILED"] = env("DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FAILED")
    globs["SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FORBIDDEN"] = env("DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FORBIDDEN")
    globs["SOCIAL_AUTH_EXCEPTION_MESSAGE_NONE_TYPE"] = env("DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_NONE_TYPE")
    globs["SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_TOKEN_ERROR"] = env("DD_SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_TOKEN_ERROR")

    # --------------------------------------------------------------------------
    # AUTH0 OAUTH2
    # --------------------------------------------------------------------------
    globs["AUTH0_OAUTH2_ENABLED"] = env("DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED")
    globs["SOCIAL_AUTH_AUTH0_KEY"] = env("DD_SOCIAL_AUTH_AUTH0_KEY")
    globs["SOCIAL_AUTH_AUTH0_SECRET"] = env("DD_SOCIAL_AUTH_AUTH0_SECRET")
    globs["SOCIAL_AUTH_AUTH0_DOMAIN"] = env("DD_SOCIAL_AUTH_AUTH0_DOMAIN")
    globs["SOCIAL_AUTH_AUTH0_SCOPE"] = env("DD_SOCIAL_AUTH_AUTH0_SCOPE")
    globs["SOCIAL_AUTH_TRAILING_SLASH"] = env("DD_SOCIAL_AUTH_TRAILING_SLASH")

    # --------------------------------------------------------------------------
    # KEYCLOAK OAUTH2
    # --------------------------------------------------------------------------
    globs["KEYCLOAK_OAUTH2_ENABLED"] = env("DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED")
    globs["SOCIAL_AUTH_KEYCLOAK_KEY"] = env("DD_SOCIAL_AUTH_KEYCLOAK_KEY")
    globs["SOCIAL_AUTH_KEYCLOAK_SECRET"] = env("DD_SOCIAL_AUTH_KEYCLOAK_SECRET")
    globs["SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY"] = env("DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY")
    globs["SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL"] = env("DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL")
    globs["SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL"] = env("DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL")
    globs["SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT"] = env("DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT")

    # --------------------------------------------------------------------------
    # GITHUB ENTERPRISE OAUTH2
    # --------------------------------------------------------------------------
    globs["GITHUB_ENTERPRISE_OAUTH2_ENABLED"] = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED")
    globs["SOCIAL_AUTH_GITHUB_ENTERPRISE_URL"] = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL")
    globs["SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL"] = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL")
    globs["SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY"] = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY")
    globs["SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET"] = env("DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET")

    # --------------------------------------------------------------------------
    # INSTALLED_APPS
    # --------------------------------------------------------------------------
    globs["INSTALLED_APPS"] += ("social_django",)

    # --------------------------------------------------------------------------
    # MIDDLEWARE
    # --------------------------------------------------------------------------
    MIDDLEWARE = globs["MIDDLEWARE"]
    if isinstance(MIDDLEWARE, list):
        MIDDLEWARE.append("dojo.sso.middleware.CustomSocialAuthExceptionMiddleware")
    else:
        globs["MIDDLEWARE"] = [*MIDDLEWARE, "dojo.sso.middleware.CustomSocialAuthExceptionMiddleware"]
        MIDDLEWARE = globs["MIDDLEWARE"]

    # --------------------------------------------------------------------------
    # TEMPLATES - add SSO context processors and template dir
    # --------------------------------------------------------------------------
    context_processors = globs["TEMPLATES"][0]["OPTIONS"]["context_processors"]
    context_processors.append("social_django.context_processors.backends")
    context_processors.append("social_django.context_processors.login_redirect")
    context_processors.append("dojo.sso.context_processors.sso_context")
    sso_template_dir = str(Path(__file__).parent / "templates")
    globs["TEMPLATES"][0]["DIRS"].append(sso_template_dir)

    # --------------------------------------------------------------------------
    # SAML2
    # --------------------------------------------------------------------------
    globs["SAML2_ENABLED"] = env("DD_SAML2_ENABLED")
    globs["SAML2_LOGIN_BUTTON_TEXT"] = env("DD_SAML2_LOGIN_BUTTON_TEXT")
    globs["SAML2_LOGOUT_URL"] = env("DD_SAML2_LOGOUT_URL")
    if globs["SAML2_ENABLED"]:
        import saml2  # noqa: PLC0415
        import saml2.saml  # noqa: PLC0415

        SAML_METADATA = {}
        if len(env("DD_SAML2_METADATA_AUTO_CONF_URL")) > 0:
            SAML_METADATA["remote"] = [{"url": env("DD_SAML2_METADATA_AUTO_CONF_URL")}]
        if len(env("DD_SAML2_METADATA_LOCAL_FILE_PATH")) > 0:
            SAML_METADATA["local"] = [env("DD_SAML2_METADATA_LOCAL_FILE_PATH")]
        globs["INSTALLED_APPS"] += ("djangosaml2",)
        MIDDLEWARE.append("djangosaml2.middleware.SamlSessionMiddleware")
        globs["AUTHENTICATION_BACKENDS"] += (env("DD_SAML2_AUTHENTICATION_BACKENDS"),)
        globs["LOGIN_EXEMPT_URLS"] += (rf"^{URL_PREFIX}saml2/",)
        globs["SAML_LOGOUT_REQUEST_PREFERRED_BINDING"] = saml2.BINDING_HTTP_POST
        globs["SAML_IGNORE_LOGOUT_ERRORS"] = True
        globs["SAML_DJANGO_USER_MAIN_ATTRIBUTE"] = "username"
        globs["SAML_USE_NAME_ID_AS_USERNAME"] = True
        globs["SAML_CREATE_UNKNOWN_USER"] = env("DD_SAML2_CREATE_USER")
        globs["SAML_ATTRIBUTE_MAPPING"] = _saml2_attrib_map_format(env("DD_SAML2_ATTRIBUTES_MAP"))
        globs["SAML_FORCE_AUTH"] = env("DD_SAML2_FORCE_AUTH")
        SAML_ALLOW_UNKNOWN_ATTRIBUTES = env("DD_SAML2_ALLOW_UNKNOWN_ATTRIBUTE")
        globs["SAML_ALLOW_UNKNOWN_ATTRIBUTES"] = SAML_ALLOW_UNKNOWN_ATTRIBUTES

        BASEDIR = Path(__file__).parent.absolute()
        if len(env("DD_SAML2_ENTITY_ID")) == 0:
            SAML2_ENTITY_ID = f"{SITE_URL}/saml2/metadata/"
        else:
            SAML2_ENTITY_ID = env("DD_SAML2_ENTITY_ID")
        globs["SAML2_ENTITY_ID"] = SAML2_ENTITY_ID

        SAML_FORCE_AUTH = env("DD_SAML2_FORCE_AUTH")

        globs["SAML_CONFIG"] = {
            # full path to the xmlsec1 binary programm
            "xmlsec_binary": "/usr/bin/xmlsec1",

            # your entity id, usually your subdomain plus the url to the metadata view
            "entityid": str(SAML2_ENTITY_ID),

            # directory with attribute mapping
            "attribute_map_dir": str(BASEDIR / "attribute_maps"),
            # do now discard attributes not specified in attribute-maps
            "allow_unknown_attributes": SAML_ALLOW_UNKNOWN_ATTRIBUTES,
            # this block states what services we provide
            "service": {
                # we are just a lonely SP
                "sp": {
                    "name": "Defect_Dojo",
                    "name_id_format": saml2.saml.NAMEID_FORMAT_TRANSIENT,
                    "want_response_signed": False,
                    "want_assertions_signed": True,
                    "force_authn": SAML_FORCE_AUTH,
                    "allow_unsolicited": True,

                    # For Okta add signed logout requets. Enable this:
                    # "logout_requests_signed": True,

                    "endpoints": {
                        # url and binding to the assetion consumer service view
                        # do not change the binding or service name
                        "assertion_consumer_service": [
                            (f"{SITE_URL}/saml2/acs/",
                            saml2.BINDING_HTTP_POST),
                        ],
                        # url and binding to the single logout service view
                        # do not change the binding or service name
                        "single_logout_service": [
                            # Disable next two lines for HTTP_REDIRECT for IDP's that only support HTTP_POST. Ex. Okta:
                            (f"{SITE_URL}/saml2/ls/",
                            saml2.BINDING_HTTP_REDIRECT),
                            (f"{SITE_URL}/saml2/ls/post",
                            saml2.BINDING_HTTP_POST),
                        ],
                    },

                    # attributes that this project need to identify a user
                    "required_attributes": ["Email", "UserName"],

                    # attributes that may be useful to have but not required
                    "optional_attributes": ["Firstname", "Lastname"],
                },
            },

            # where the remote metadata is stored, local, remote or mdq server.
            # One metadatastore or many ...
            "metadata": SAML_METADATA,

            # set to 1 to output debugging information
            "debug": 0,

            # own metadata settings
            "contact_person": [
                {"given_name": "Lorenzo",
                "sur_name": "Gil",
                "company": "Yaco Sistemas",
                "email_address": "lgs@yaco.es",
                "contact_type": "technical"},
                {"given_name": "Angel",
                "sur_name": "Fernandez",
                "company": "Yaco Sistemas",
                "email_address": "angel@yaco.es",
                "contact_type": "administrative"},
            ],
            # you can set multilanguage information here
            "organization": {
                "name": [("Yaco Sistemas", "es"), ("Yaco Systems", "en")],
                "display_name": [("Yaco", "es"), ("Yaco", "en")],
                "url": [("http://www.yaco.es", "es"), ("http://www.yaco.com", "en")],
            },
            "valid_for": 24,  # how long is our metadata valid
        }

    # --------------------------------------------------------------------------
    # REMOTE_USER
    # --------------------------------------------------------------------------
    globs["AUTH_REMOTEUSER_ENABLED"] = env("DD_AUTH_REMOTEUSER_ENABLED")
    globs["AUTH_REMOTEUSER_USERNAME_HEADER"] = env("DD_AUTH_REMOTEUSER_USERNAME_HEADER")
    globs["AUTH_REMOTEUSER_EMAIL_HEADER"] = env("DD_AUTH_REMOTEUSER_EMAIL_HEADER")
    globs["AUTH_REMOTEUSER_FIRSTNAME_HEADER"] = env("DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER")
    globs["AUTH_REMOTEUSER_LASTNAME_HEADER"] = env("DD_AUTH_REMOTEUSER_LASTNAME_HEADER")
    globs["AUTH_REMOTEUSER_GROUPS_HEADER"] = env("DD_AUTH_REMOTEUSER_GROUPS_HEADER")
    globs["AUTH_REMOTEUSER_GROUPS_CLEANUP"] = env("DD_AUTH_REMOTEUSER_GROUPS_CLEANUP")
    globs["AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER"] = env("DD_AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER")

    AUTH_REMOTEUSER_TRUSTED_PROXY = IPSet()
    for ip_range in env("DD_AUTH_REMOTEUSER_TRUSTED_PROXY"):
        AUTH_REMOTEUSER_TRUSTED_PROXY.add(IPNetwork(ip_range))
    globs["AUTH_REMOTEUSER_TRUSTED_PROXY"] = AUTH_REMOTEUSER_TRUSTED_PROXY

    if env("DD_AUTH_REMOTEUSER_LOGIN_ONLY"):
        RemoteUserMiddleware = "dojo.sso.remote_user.PersistentRemoteUserMiddleware"
    else:
        RemoteUserMiddleware = "dojo.sso.remote_user.RemoteUserMiddleware"
    # we need to add middleware just behind AuthenticationMiddleware
    for i in range(len(MIDDLEWARE)):
        if MIDDLEWARE[i] == "django.contrib.auth.middleware.AuthenticationMiddleware":
            MIDDLEWARE.insert(i + 1, RemoteUserMiddleware)
            break

    if globs["AUTH_REMOTEUSER_ENABLED"]:
        globs["REST_FRAMEWORK"]["DEFAULT_AUTHENTICATION_CLASSES"] = \
            ("dojo.sso.remote_user.RemoteUserAuthentication",) + \
            globs["REST_FRAMEWORK"]["DEFAULT_AUTHENTICATION_CLASSES"]
