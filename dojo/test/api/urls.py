from dojo.test.api.views import TestImportViewSet, TestsViewSet, TestTypesViewSet


def add_test_urls(router):
    router.register("tests", TestsViewSet, basename="test")
    router.register("test_types", TestTypesViewSet, basename="test_type")
    router.register("test_imports", TestImportViewSet, basename="test_imports")
    return router
