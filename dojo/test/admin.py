from django.contrib import admin

from dojo.test.models import Test, Test_Import, Test_Type


@admin.register(Test_Type)
class Test_TypeAdmin(admin.ModelAdmin):

    """Admin support for the Test_Type model."""


@admin.register(Test)
class TestAdmin(admin.ModelAdmin):

    """Admin support for the Test model."""


@admin.register(Test_Import)
class Test_ImportAdmin(admin.ModelAdmin):

    """Admin support for the Test_Import model."""
