from dojo.organization.api.views import (
    OrganizationViewSet,
)


def add_organization_urls(router):
    router.register(r"organizations", OrganizationViewSet, basename="organization")
    # RBAC alias endpoints moved to Pro under legacy authorization:
    #   organization_members, organization_groups →
    #   pro/product_type_members, pro/product_type_groups
    return router
