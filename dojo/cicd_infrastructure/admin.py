from django.contrib import admin

from dojo.cicd_infrastructure.models import CICDInfrastructure


@admin.register(CICDInfrastructure)
class CICDInfrastructureAdmin(admin.ModelAdmin):

    """Admin support for the CICDInfrastructure model."""
