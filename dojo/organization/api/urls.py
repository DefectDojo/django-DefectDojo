from dojo.organization.api.views import (
    OrganizationGroupViewSet,
    OrganizationMemberViewSet,
    OrganizationViewSet,
)


def add_organization_urls(router):
    router.register(r"organizations", OrganizationViewSet, basename="organization")
    router.register(r"organization_members", OrganizationMemberViewSet, basename="organization_member")
    router.register(r"organization_groups", OrganizationGroupViewSet, basename="organization_group")
    return router
