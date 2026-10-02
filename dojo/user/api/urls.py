from dojo.user.api.views import UserContactInfoViewSet, UsersViewSet


def add_user_urls(router):
    router.register(r"users", UsersViewSet, basename="user")
    router.register(r"user_contact_infos", UserContactInfoViewSet, basename="usercontactinfo")
    return router
