from django.test import TestCase
from dojo.models import Product, Engagement, Test, Finding, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    User, ScanSettings, Scan, Stub_Finding, Endpoint, JIRA_PKey, JIRA_Conf, \
    Finding_Template, App_Analysis

from dojo.api_v2.views import EndPointViewSet, EngagementViewSet, \
    FindingTemplatesViewSet, FindingViewSet, JiraConfigurationsViewSet, \
    JiraIssuesViewSet, JiraViewSet, ProductViewSet, ScanSettingsViewSet, \
    ScansViewSet, StubFindingsViewSet, TestsViewSet, \
    ToolConfigurationsViewSet, ToolProductSettingsViewSet, ToolTypesViewSet, \
    UsersViewSet, ImportScanView


class TaggitTests(TestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self, *args, **kwargs):
        pass

    def test_tags_prefetching(self):
        print('\nadding tags')
        for product in Product.objects.all():
            # print(product.name)
            # print('existing: ', product.tags)
            product.tags = self.add_tags(product.tags, ['product_' + str(product.id)])
            # print('new: ', product.tags)
            product.save()
            for eng in product.engagement_set.all():
                # print('engagement: ', eng)
                eng.tags = self.add_tags(eng.tags, ['eng_' + str(eng.id), 'product_' + str(product.id)])
                eng.save()

        print('testing tags for correctness without prefetching')
        self.check_tags(Product.objects.all())

        print('testing tags for correctness with prefetching')
        self.check_tags(Product.objects.all().prefetch_related('tagged_items__tag'))

        print('testing tags for correctness with nested prefetching')
        self.check_tags(Product.objects.all().prefetch_related('tagged_items__tag', 'engagement_set__tagged_items__tag'))


    def add_tags(self, curr_tags, extra_tags):
            for tag in extra_tags:
                curr_tags.append(tag)
            # print(", ".join(curr_tags))
            return ", ".join(curr_tags)

    def check_tags(self, queryset):
        for product in queryset:
            print(product.name + ": " + str(product.tags))
            self.assertEqual(len(product.tags), 1)
            self.assertEqual(product.tags[0], 'product_' + str(product.id))
            for eng in product.engagement_set.all():
                print("         :" + eng.name + ": " + str(eng.tags))
                self.assertEqual(len(eng.tags), 2)
                self.assertEqual('product_' + str(product.id) in product.tags, True)
                self.assertEqual('eng_' + str(eng.id) in eng.tags, True)
                self.assertEqual('eng_' + str(eng.id + 1) in eng.tags, False)
