from rest_framework import viewsets, mixins
from rest_framework.permissions import DjangoModelPermissions
from django_filters.rest_framework import DjangoFilterBackend

from dojo.models import Product, Engagement, Test, Finding, \
    User, ScanSettings, Scan, Stub_Finding, Finding_Template, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    Endpoint, JIRA_PKey, JIRA_Conf

from dojo.api_v2 import serializers, permissions


class EndPointViewSet(mixins.ListModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
                      mixins.DestroyModelMixin,
                      mixins.CreateModelMixin,
                      viewsets.GenericViewSet):
    serializer_class = serializers.EndpointSerializer
    queryset = Endpoint.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'host', 'product')


class EngagementViewSet(mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        mixins.UpdateModelMixin,
                        mixins.CreateModelMixin,
                        viewsets.GenericViewSet):
    serializer_class = serializers.EngagementSerializer
    queryset = Engagement.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'active', 'eng_type', 'target_start',
                     'target_end', 'requester', 'report_type',
                     'updated', 'threat_model', 'api_test',
                     'pen_test', 'status', 'product')


class FindingTemplatesViewSet(mixins.ListModelMixin,
                              mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin,
                              mixins.CreateModelMixin,
                              viewsets.GenericViewSet):
    serializer_class = serializers.FindingTemplateSerializer
    queryset = Finding_Template.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'title', 'cwe', 'severity', 'description',
                     'mitigation')


class FindingViewSet(mixins.ListModelMixin,
                     mixins.RetrieveModelMixin,
                     mixins.UpdateModelMixin,
                     mixins.CreateModelMixin,
                     viewsets.GenericViewSet):
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


class JiraConfigurationsViewSet(mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                mixins.DestroyModelMixin,
                                mixins.UpdateModelMixin,
                                mixins.CreateModelMixin,
                                viewsets.GenericViewSet):
    serializer_class = serializers.JIRAConfSerializer
    queryset = JIRA_Conf.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'url')


class JiraIssuesViewSet(mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        mixins.DestroyModelMixin,
                        mixins.CreateModelMixin,
                        mixins.UpdateModelMixin,
                        viewsets.GenericViewSet):
    serializer_class = serializers.JIRAIssueSerializer
    queryset = JIRA_Issue.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'jira_id', 'jira_key')


class JiraViewSet(mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.DestroyModelMixin,
                  mixins.UpdateModelMixin,
                  mixins.CreateModelMixin,
                  viewsets.GenericViewSet):
    serializer_class = serializers.JIRASerializer
    queryset = JIRA_PKey.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'conf', 'product', 'component', 'project_key',
                     'push_all_issues', 'enable_engagement_epic_mapping',
                     'push_notes')


class ProductViewSet(mixins.ListModelMixin,
                     mixins.RetrieveModelMixin,
                     mixins.CreateModelMixin,
                     mixins.UpdateModelMixin,
                     viewsets.GenericViewSet):
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


class ScanSettingsViewSet(mixins.ListModelMixin,
                          mixins.RetrieveModelMixin,
                          mixins.DestroyModelMixin,
                          mixins.UpdateModelMixin,
                          mixins.CreateModelMixin,
                          viewsets.GenericViewSet):
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


class ScansViewSet(mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   viewsets.GenericViewSet):
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


class StubFindingsViewSet(mixins.ListModelMixin,
                          mixins.RetrieveModelMixin,
                          mixins.CreateModelMixin,
                          mixins.UpdateModelMixin,
                          viewsets.GenericViewSet):
    serializer_class = serializers.StubFindingSerializer
    queryset = Stub_Finding.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'title', 'date', 'severity', 'description')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return serializers.StubFindingCreateSerializer
        else:
            return serializers.StubFindingSerializer


class TestsViewSet(mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   mixins.CreateModelMixin,
                   viewsets.GenericViewSet):
    serializer_class = serializers.TestSerializer
    queryset = Test.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'test_type', 'target_start', 'target_end', 'notes',
                     'percent_complete', 'actual_time', 'engagement')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return serializers.TestCreateSerializer
        else:
            return serializers.TestSerializer


class ToolConfigurationsViewSet(mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                mixins.CreateModelMixin,
                                mixins.UpdateModelMixin,
                                mixins.DestroyModelMixin,
                                viewsets.GenericViewSet):
    serializer_class = serializers.ToolConfigurationSerializer
    queryset = Tool_Configuration.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'tool_type', 'url', 'authentication_type')


class ToolProductSettingsViewSet(mixins.ListModelMixin,
                                 mixins.RetrieveModelMixin,
                                 mixins.DestroyModelMixin,
                                 mixins.CreateModelMixin,
                                 mixins.UpdateModelMixin,
                                 viewsets.GenericViewSet):
    serializer_class = serializers.ToolProductSettingsSerializer
    queryset = Tool_Product_Settings.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'product', 'tool_configuration',
                     'tool_project_id', 'url')


class ToolTypesViewSet(mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.CreateModelMixin,
                       mixins.UpdateModelMixin,
                       viewsets.GenericViewSet):
    serializer_class = serializers.ToolTypeSerializer
    queryset = Tool_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'name', 'description')


class UsersViewSet(mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   viewsets.GenericViewSet):
    serializer_class = serializers.UserSerializer
    queryset = User.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('id', 'username', 'first_name', 'last_name')


class ImportScanView(mixins.CreateModelMixin,
                     viewsets.GenericViewSet):
    serializer_class = serializers.ImportScanSerializer
    queryset = Test.objects.all()


class ReImportScanView(mixins.CreateModelMixin,
                       viewsets.GenericViewSet):
    serializer_class = serializers.ReImportScanSerializer
    queryset = Test.objects.all()
