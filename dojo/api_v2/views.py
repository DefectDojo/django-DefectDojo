from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import mixins, viewsets
from rest_framework.permissions import DjangoModelPermissions
from rest_framework.decorators import detail_route

from dojo.engagement.services import close_engagement, reopen_engagement
from dojo.models import Product, Product_Type, Engagement, Test, Test_Type, Finding, \
    User, ScanSettings, Scan, Stub_Finding, Finding_Template, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    Endpoint, JIRA_PKey, JIRA_Conf, DojoMeta, Development_Environment
from dojo.api_v2 import serializers, permissions


class CRUModelViewSet(
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        mixins.CreateModelMixin,
        mixins.UpdateModelMixin,
        viewsets.GenericViewSet
):
    """A view set supporting anything except for deletion."""


class EndPointViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.EndpointSerializer
    queryset = Endpoint.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'host', 'product')


class EngagementViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.EngagementSerializer
    queryset = Engagement.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'active', 'eng_type', 'target_start',
                     'target_end', 'requester', 'report_type',
                     'updated', 'threat_model', 'api_test',
                     'pen_test', 'status', 'product')

    @detail_route(methods=["post"])
    def close(self, request, pk=None):
        eng = get_object_or_404(Engagement.objects, id=pk)
        close_engagement(eng)
        return HttpResponse()

    @detail_route(methods=["post"])
    def reopen(self, request, pk=None):
        eng = get_object_or_404(Engagement.objects, id=pk)
        reopen_engagement(eng)
        return HttpResponse()


class FindingTemplatesViewSet(CRUModelViewSet):
    serializer_class = serializers.FindingTemplateSerializer
    queryset = Finding_Template.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'title', 'cwe', 'severity', 'description',
                     'mitigation')


class FindingViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.FindingSerializer
    queryset = Finding.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'title', 'date', 'severity', 'description',
                     'mitigated', 'endpoints', 'test', 'active', 'verified',
                     'false_p', 'reporter', 'url', 'out_of_scope',
                     'duplicate', 'test__engagement__product',
                     'test__engagement')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return serializers.FindingCreateSerializer
        else:
            return serializers.FindingSerializer


class JiraConfigurationsViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.JIRAConfSerializer
    queryset = JIRA_Conf.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'url')


class JiraIssuesViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.JIRAIssueSerializer
    queryset = JIRA_Issue.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'jira_id', 'jira_key')


class JiraViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.JIRASerializer
    queryset = JIRA_PKey.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'conf', 'product', 'component', 'project_key',
                     'push_all_issues', 'enable_engagement_epic_mapping',
                     'push_notes')


class DojoMetaViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.MetaSerializer
    queryset = DojoMeta.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'product', 'endpoint', 'name')


class ProductViewSet(CRUModelViewSet):
    serializer_class = serializers.ProductSerializer
    # TODO: prefetch
    queryset = Product.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.UserHasProductPermission,
                          DjangoModelPermissions)
    # TODO: findings count field
    filter_fields = ('id', 'name', 'prod_type', 'created', 'authorized_users')

    def get_queryset(self):
        if not self.request.user.is_staff:
            return Product.objects.filter(
                authorized_users__in=[self.request.user])
        else:
            return Product.objects.all()


class ProductTypeViewSet(CRUModelViewSet):
    serializer_class = serializers.ProductTypeSerializer
    queryset = Product_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'critical_product',
                     'key_product', 'created', 'updated')


class ScanSettingsViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.ScanSettingsSerializer
    queryset = ScanSettings.objects.all()
    permission_classes = (permissions.UserHasScanSettingsPermission,
                          DjangoModelPermissions)
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'date', 'user', 'frequency', 'product', 'addresses')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return serializers.ScanSettingsCreateSerializer
        else:
            return serializers.ScanSettingsSerializer

    def get_queryset(self):
        if not self.request.user.is_staff:
            return ScanSettings.objects.filter(
                product__authorized_users__in=[self.request.user])
        else:
            return ScanSettings.objects.all()


class ScansViewSet(viewsets.ReadOnlyModelViewSet):
    # TODO: ipscans
    serializer_class = serializers.ScanSerializer
    queryset = Scan.objects.all()
    permission_classes = (permissions.UserHasScanPermission,
                          DjangoModelPermissions)
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'date', 'scan_settings')

    def get_queryset(self):
        if not self.request.user.is_staff:
            return Scan.objects.filter(
                scan_settings__product__authorized_users__in=[self.request.user])
        else:
            return Scan.objects.all()


class StubFindingsViewSet(CRUModelViewSet):
    serializer_class = serializers.StubFindingSerializer
    queryset = Stub_Finding.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'title', 'date', 'severity', 'description')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return serializers.StubFindingCreateSerializer
        else:
            return serializers.StubFindingSerializer


class DevelopmentEnvironmentViewSet(CRUModelViewSet):
    serializer_class = serializers.DevelopmentEnvironmentSerializer
    queryset = Development_Environment.objects.all()
    filter_backends = (DjangoFilterBackend,)


class TestsViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.TestSerializer
    queryset = Test.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'title', 'test_type', 'target_start',
                     'target_end', 'notes', 'percent_complete',
                     'actual_time', 'engagement')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return serializers.TestCreateSerializer
        else:
            return serializers.TestSerializer


class TestTypesViewSet(CRUModelViewSet):
    serializer_class = serializers.TestTypeSerializer
    queryset = Test_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)


class ToolConfigurationsViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.ToolConfigurationSerializer
    queryset = Tool_Configuration.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'tool_type', 'url', 'authentication_type')


class ToolProductSettingsViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.ToolProductSettingsSerializer
    queryset = Tool_Product_Settings.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'product', 'tool_configuration',
                     'tool_project_id', 'url')


class ToolTypesViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.ToolTypeSerializer
    queryset = Tool_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'description')


class UsersViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = serializers.UserSerializer
    queryset = User.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'username', 'first_name', 'last_name')


class ImportScanViewSet(
        mixins.CreateModelMixin,
        viewsets.GenericViewSet
):
    serializer_class = serializers.ImportScanSerializer
    queryset = Test.objects.all()


class ReImportScanViewSet(
        mixins.CreateModelMixin,
        viewsets.GenericViewSet
):
    serializer_class = serializers.ReImportScanSerializer
    queryset = Test.objects.all()
