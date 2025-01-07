import logging
import re

import gitlab
import requests
import json
import social_core.pipeline.user
from django.conf import settings
from social_core.backends.azuread_tenant import AzureADTenantOAuth2
from social_core.backends.google import GoogleOAuth2

from dojo.authorization.roles_permissions import Permissions, Roles
from dojo.models import Dojo_Group, Dojo_Group_Member, Product, Product_Member, Product_Type,Product_Type_Member,Global_Role, Role, UserContactInfo
from dojo.product.queries import get_authorized_products
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from dojo.utils import get_remote_json_config
from django.contrib import messages

logger = logging.getLogger(__name__)


def social_uid(backend, details, response, *args, **kwargs):
    if settings.AZUREAD_TENANT_OAUTH2_ENABLED and isinstance(backend, AzureADTenantOAuth2):
        """Return user details from Azure AD account"""
        fullname, first_name, last_name, upn = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
            response.get("upn"),
        )
        uid = backend.get_user_id(details, response)
        return {"username": upn,
                "email": upn,
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
                "uid": uid}
    if settings.GOOGLE_OAUTH_ENABLED and isinstance(backend, GoogleOAuth2):
        """Return user details from Google account"""
        if "sub" in response:
            google_uid = response["sub"]
        elif "email" in response:
            google_uid = response["email"]
        else:
            google_uid = response["id"]
        fullname, first_name, last_name, email = (
            response.get("fullname", ""),
            response.get("first_name", ""),
            response.get("last_name", ""),
            response.get("email"),
        )
        return {"username": email,
                "email": email,
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
                "uid": google_uid}
    uid = backend.get_user_id(details, response)
    # Used for most backends
    if uid:
        return {"uid": uid}
    # Until OKTA PR in social-core is merged
    # This modified way needs to work
    return {"uid": response.get("preferred_username")}


def modify_permissions(backend, uid, user=None, social=None, *args, **kwargs):
    pass


def update_azure_groups(backend, uid, user=None, social=None, *args, **kwargs):
    if (
        settings.AZUREAD_TENANT_OAUTH2_ENABLED
        and settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS
        and isinstance(backend, AzureADTenantOAuth2)
    ):
        # In some wild cases, there could be two social auth users
        # connected to the same DefectDojo user. Grab the newest one
        soc = user.social_auth.order_by("-created").first()
        token = soc.extra_data["access_token"]
        group_names = search_azure_groups(kwargs, token, soc)
        if len(group_names) > 0:
            assign_user_to_groups(user, group_names, "AzureAD")
        if settings.AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS:
            cleanup_old_groups_for_user(user, group_names)


def search_azure_groups(kwargs, token, soc):
    group_names = []
    if "groups" not in kwargs["response"] or kwargs["response"]["groups"] == "":
        logger.warning("No groups in response. Stopping to update product type of user based on azureAD")
        return
    group_ids = kwargs["response"]["groups"]
    for group_from_response in group_ids:
        try:
            logger.debug("Analysing Group_ID " + group_from_response)
            request_headers = {"Authorization": "Bearer " + token}
            if is_group_id(group_from_response):
                logger.debug(
                    "detected "
                    + group_from_response
                    + " as groupID and will fetch the displayName from microsoft graph"
                )
                group_name_request = requests.get(
                    (
                        str(soc.extra_data["resource"])
                        + "/v1.0/groups/"
                        + str(group_from_response)
                        + "?$select=displayName"
                    ),
                        headers=request_headers,
                        timeout=settings.REQUESTS_TIMEOUT,
                    )
                group_name_request.raise_for_status()
                group_name_request_json = group_name_request.json()
                group_name = group_name_request_json["displayName"]
            else:
                logger.debug("detected " + group_from_response + " as group name and will not call microsoft graph")
                group_name = group_from_response

            if settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER == "" or re.search(
                settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER, group_name
            ):
                group_names.append(group_name)
            else:
                logger.debug(
                    "Skipping group "
                    + group_name
                    + " due to AZUREAD_TENANT_OAUTH2_GROUPS_FILTER "
                    + settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER
                )
                continue
        except Exception as e:
            logger.error(f"Could not call microsoft graph API or save groups to member: {e}")
    return group_names


def is_group_id(group):
    return bool(re.search("^[a-zA-Z0-9]{8,}-[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{4,}-[a-zA-Z0-9]{12,}$", group))


def assign_user_to_groups(user, group_names, social_provider):
    for group_name in group_names:
        group, created_group = Dojo_Group.objects.get_or_create(name=group_name, social_provider=social_provider)
        if created_group:
            logger.debug("Group %s for social provider %s was created", str(group), social_provider)
        _group_member, is_member_created = Dojo_Group_Member.objects.get_or_create(group=group, user=user, defaults={
            "role": Role.objects.get(id=Roles.Maintainer)})
        if is_member_created:
            logger.debug("User %s become member of group %s (social provider: %s)", user, str(group), social_provider)


def cleanup_old_groups_for_user(user, group_names):
    for group_member in Dojo_Group_Member.objects.select_related("group").filter(user=user):
        group = group_member.group
        if str(group) not in group_names:
            logger.debug("Deleting membership of user %s from %s group %s", user, group.social_provider, str(group))
            group_member.delete()


def update_product_type_azure_devops(backend, uid, user=None, social=None, *args, **kwargs):
    if (
        settings.AZUREAD_TENANT_OAUTH2_ENABLED
        and settings.AZURE_DEVOPS_PERMISSION_AUTO_IMPORT
        and isinstance(backend, AzureADTenantOAuth2)
    ):
        soc = user.social_auth.get()
        token = soc.extra_data["access_token"]
        group_names = search_azure_groups(kwargs, token, soc)
        logger.debug("detected groups " + str(group_names))
        groups_validate = settings.AZURE_DEVOPS_MAIN_SECURITY_GROUP.split(',')
        if (
            group_names is not None
            and len(group_names) > 0
            and any(map(group_names.__contains__, groups_validate))
        ):
            if settings.DD_VALIDATE_ROLE_USER:
                UserContactInfo.objects.update_or_create(user=user, defaults={"title": ", ".join(group_names)})
            user_login = kwargs["details"]["email"]
            request_headers = {"Authorization": "Bearer " + token}
            graph_user_request = requests.get(
                (str(soc.extra_data["resource"]) + "/v1.0/users/" + user_login), headers=request_headers
            )
            graph_user_request.raise_for_status()
            graph_user_request_json = graph_user_request.json()
            job_title = graph_user_request_json["jobTitle"]
            office_location = graph_user_request_json["officeLocation"]
            logger.debug("detected jobTitle " + job_title + " and officeLocation " + office_location)

            # Assign global role
            if office_location in settings.AZURE_DEVOPS_OFFICES_LOCATION.split(",")[1]:
                Global_Role.objects.get_or_create(user=user, role=Role.objects.get(id=Roles.Maintainer))
            elif office_location in settings.AZURE_DEVOPS_OFFICES_LOCATION.split(",")[2]:
                Global_Role.objects.get_or_create(user=user, role=Role.objects.get(id=Roles.Reader))
            elif office_location in settings.AZURE_DEVOPS_OFFICES_LOCATION.split(",")[3]:
                Global_Role.objects.get_or_create(user=user, role=Role.objects.get(id=Roles.Risk))

            # Assign specific role
            organization_url = settings.AZURE_DEVOPS_ORGANIZATION_URL
            token = settings.AZURE_DEVOPS_TOKEN

            credentials = BasicAuthentication("", token)
            connection = Connection(base_url=organization_url, creds=credentials)

            graph_client = connection.clients.get_graph_client()
            result_query_subjects = graph_client.query_subjects({"query": user_login, "subjectKind": ["User"]})
            
            # Get user's current product types names
            user_product_types_names = [
                prod.product_type.name
                for prod in Product_Type_Member.objects.select_related("user").filter(user=user)
            ]

            role_assigned = {"role": Role.objects.get(id=Roles.Developer)}
            is_leader = any(any(sub_part in job_title for sub_part in part.split("-")) for part in settings.AZURE_DEVOPS_JOBS_TITLE.split(",")[:2])
            if is_leader:
                role_assigned = {"role": Role.objects.get(id=Roles.Leader)}
                assign_product_type_product_to_leaders(user, job_title, office_location, role_assigned, connection, user_login, user_product_types_names)

            if result_query_subjects is not None and len(result_query_subjects) > 0:
                # Get user's product type for become member
                result_memberships = graph_client.get_membership(result_query_subjects[0].descriptor, None)

                group_team_leve1 = custom_filter_group(
                    result_memberships.additional_properties["value"],
                    graph_client,
                    settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[0],
                )
                
                if group_team_leve1 is not None:
                    group_team_leve2 = custom_filter_group(
                        graph_client.get_membership(group_team_leve1.descriptor, None).additional_properties["value"],
                        graph_client,
                        settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[1],
                    )

                    # create a new product type or update product's type authorized_users
                    if group_team_leve2 is not None and user_login.split("@")[0] not in settings.AZURE_DEVOPS_USERS_EXCLUDED_TPM:
                        if group_team_leve2.display_name not in user_product_types_names:
                            try:
                                # Check if there is a product type with the name
                                product_type = Product_Type.objects.get(name=group_team_leve2.display_name)
                            except Product_Type.DoesNotExist:
                                # If not, create a product type with that name
                                product_type = Product_Type(name=group_team_leve2.display_name)
                                product_type.save()
                            Product_Type_Member.objects.get_or_create(
                                product_type=product_type, user=user, defaults=role_assigned
                            )
                            logger.debug(
                                "User %s become member of product type %s with the role %s",
                                user,
                                product_type.name,
                                role_assigned["role"],
                            )

                        # if user is not project type member any more, remove him from list of product type members
                        for product_type_name in user_product_types_names:
                            if (
                                product_type_name != group_team_leve2.display_name
                            ):
                                product_type = Product_Type.objects.get(name=product_type_name)
                                Product_Type_Member.objects.filter(product_type=product_type, user=user).delete()
                                logger.debug(
                                    "Deleting membership of user %s from product type %s", user, product_type_name
                                )
                    else:
                        clean_project_type_user(user_product_types_names, user, user_login, is_leader)
                else:
                    clean_project_type_user(user_product_types_names, user, user_login, is_leader)
        else:
            message = f"The user is not a member of any of the app's security groups. {groups_validate}"
            messages.error(
            backend.strategy.request, message, extra_tags="alert-danger"
        )
            raise Exception(message)
           

def assign_product_type_product_to_leaders(user, job_title, office_location, role_assigned, connection, user_login, user_product_types_names):
    conf_jobs = settings.AZURE_DEVOPS_JOBS_TITLE.split(",")
    if any(sub_part in job_title for sub_part in conf_jobs[0].split("-")):
        Product.objects.filter(
            description__contains=re.sub(conf_jobs[2], "", office_location).replace(" ", "-")
        ).update(team_manager=user)
    if any(sub_part in job_title for sub_part in conf_jobs[1].split("-")):
        keys = [
            (key_pt, key_user)
            for key_pt, value in get_remote_json_config(connection, settings.AZURE_DEVOPS_REMOTE_CONFIG_FILE_PATH.split(",")[0]).items()
            for key_user, val in value.items()
            if val.lower() == user_login.lower()
        ]
        for pt_key, user_key in keys:
            pt = Product_Type.objects.filter(name=pt_key)
            if pt.exists():
                pt.update(**{json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[2])[user_key]: user})
                if pt_key not in user_product_types_names:
                    Product_Type_Member.objects.get_or_create(product_type=pt[0], user=user, defaults=role_assigned)
                    logger.debug(
                        "User %s become member of product type %s with the role %s",
                        user,
                        pt,
                        role_assigned["role"],
                    )


def clean_project_type_user(user_product_types_names, user, user_login, is_leader):
    if (user_login.split("@")[0] not in settings.AZURE_DEVOPS_USERS_EXCLUDED_TPM) and is_leader is False:
        for product_type_name in user_product_types_names:
            product_type = Product_Type.objects.get(name=product_type_name)
            Product_Type_Member.objects.filter(product_type=product_type, user=user).delete()
            logger.debug("Deleting membership of user %s from product type %s", user, product_type_name)


def custom_filter_group(result, graph_client, regex):
    for member in result:
        result_get_group = graph_client.get_group(member["containerDescriptor"])
        if (
            re.match(r"" + regex, result_get_group.display_name)
            and settings.AZURE_DEVOPS_OFFICES_LOCATION.split(",")[0] in result_get_group.principal_name
        ):
            return result_get_group


def update_product_access(backend, uid, user=None, social=None, *args, **kwargs):
    if settings.GITLAB_PROJECT_AUTO_IMPORT is True:
        # Get user's product names
        user_product_names = [prod.name for prod in get_authorized_products(Permissions.Product_View, user)]
        # Get Gitlab access token
        soc = user.social_auth.get()
        token = soc.extra_data["access_token"]
        # Get user's projects list on Gitlab
        gl = gitlab.Gitlab(settings.SOCIAL_AUTH_GITLAB_API_URL, oauth_token=token)
        # Get each project path_with_namespace as future product name
        projects = gl.projects.list(
            membership=True, min_access_level=settings.GITLAB_PROJECT_MIN_ACCESS_LEVEL, all=True
        )
        project_names = [project.path_with_namespace for project in projects]
        # Create product_type if necessary
        product_type, _created = Product_Type.objects.get_or_create(name="Gitlab Import")
        # For each project: create a new product or update product's authorized_users
        for project in projects:
            if project.path_with_namespace not in user_product_names:
                try:
                    # Check if there is a product with the name of the GitLab project
                    product = Product.objects.get(name=project.path_with_namespace)
                except Product.DoesNotExist:
                    # If not, create a product with that name and the GitLab product type
                    product = Product(name=project.path_with_namespace, prod_type=product_type)
                    product.save()
                _product_member, _created = Product_Member.objects.get_or_create(product=product, user=user, defaults={"role": Role.objects.get(id=Roles.Owner)})
                # Import tags and/orl URL if necessary
                if settings.GITLAB_PROJECT_IMPORT_TAGS:
                    if hasattr(project, "topics"):
                        if len(project.topics) > 0:
                            product.tags = ",".join(project.topics)
                    elif hasattr(project, "tag_list") and len(project.tag_list) > 0:
                        product.tags = ",".join(project.tag_list)
                if settings.GITLAB_PROJECT_IMPORT_URL:
                    if hasattr(project, "web_url") and len(project.web_url) > 0:
                        product.description = "[" + project.web_url + "](" + project.web_url + ")"
                if settings.GITLAB_PROJECT_IMPORT_TAGS or settings.GITLAB_PROJECT_IMPORT_URL:
                    product.save()

        # For each product: if user is not project member any more, remove him from product's list of product members
        for product_name in user_product_names:
            if product_name not in project_names:
                product = Product.objects.get(name=product_name)
                Product_Member.objects.filter(product=product, user=user).delete()


def sanitize_username(username):
    allowed_chars_regex = re.compile(r"[\w@.+_-]")
    allowed_chars = filter(lambda char: allowed_chars_regex.match(char), list(username))
    return "".join(allowed_chars)


def create_user(strategy, details, backend, user=None, *args, **kwargs):
    if not settings.SOCIAL_AUTH_CREATE_USER:
        return None
    details["username"] = sanitize_username(details.get("username"))
    return social_core.pipeline.user.create_user(strategy, details, backend, user, args, kwargs)
