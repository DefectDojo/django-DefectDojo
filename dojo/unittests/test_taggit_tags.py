from dojo.models import Product, Finding
from .dojo_test_case import DojoAPITestCase
import logging

logger = logging.getLogger(__name__)


class TaggitTests(DojoAPITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self, *args, **kwargs):
        super().setUp()
        self.login_as_admin()
        self.scans_path = 'dojo/unittests/scans/zap/'
        self.zap_sample5_filename = self.scans_path + '5_zap_sample_one.xml'

    def test_tags_prefetching(self):
        # print('\nadding tags')
        for product in Product.objects.all():
            product.tags = self.add_tags(product.tags, ['product_' + str(product.id)])
            product.save()
            for eng in product.engagement_set.all():
                eng.tags = self.add_tags(eng.tags, ['eng_' + str(eng.id), 'product_' + str(product.id)])
                eng.save()
                for test in eng.test_set.all():
                    test.tags = self.add_tags(test.tags, ['test_' + str(test.id), 'eng_' + str(eng.id), 'product_' + str(product.id)])
                    test.save()

        # print('testing tags for correctness without prefetching')
        self.check_tags(Product.objects.all())

        # print('testing tags for correctness with prefetching')
        self.check_tags(Product.objects.all().prefetch_related('tagged_items__tag'))

        # print('testing tags for correctness with nested prefetching')
        self.check_tags(Product.objects.all().prefetch_related('tagged_items__tag', 'engagement_set__tagged_items__tag'))

    def add_tags(self, curr_tags, extra_tags):
        for tag in extra_tags:
            curr_tags.append(tag)
        return ", ".join(curr_tags)

    def check_tags(self, queryset):
        for product in queryset:
            # print(product.name + ": " + str(product.tags))
            self.assertEqual(len(product.tags), 1)
            self.assertEqual(product.tags[0].name, 'product_' + str(product.id))
            for eng in product.engagement_set.all():
                # print("         :" + eng.name + ": " + str(eng.tags))
                self.assertEqual(len(eng.tags), 2)
                self.assertEqual('product_' + str(product.id) in [tag.name for tag in product.tags], True)
                self.assertEqual('eng_' + str(eng.id) in [tag.name for tag in eng.tags], True)
                self.assertEqual('eng_' + str(eng.id + 1) in [tag.name for tag in eng.tags], False)
                for test in eng.test_set.all():
                    # print("         :" + eng.name + ": " + test.test_type.name + ": " + str(test.tags))
                    self.assertEqual(len(test.tags), 3)
                    self.assertEqual('product_' + str(product.id) in [tag.name for tag in product.tags], True)
                    self.assertEqual('eng_' + str(eng.id) in [tag.name for tag in eng.tags], True)
                    self.assertEqual('eng_' + str(eng.id + 1) in [tag.name for tag in eng.tags], False)
                    self.assertEqual('test_' + str(test.id) in [tag.name for tag in test.tags], True)
                    self.assertEqual('test_' + str(test.id + 1) in [tag.name for tag in test.tags], False)

    def create_finding_with_tags(self, tags):
        finding_id = Finding.objects.all().first().id
        finding_details = self.get_finding_api(finding_id)

        del finding_details['id']

        finding_details['title'] = 'tags test 1'
        finding_details['tags'] = tags
        response = self.post_new_finding_api(finding_details)

        return response['id']

    def test_finding_get_tags(self):
        tags = ['tag1', 'tag2']
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        self.assertEqual(len(tags), len(response.get('tags', None)))
        for tag in tags:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_finding_post_tags(self):
        # create finding
        tags = ['tag1', 'tag2']
        finding_id = self.create_finding_with_tags(tags)

        # post tags. POST will ADD tags to existing tags (which is possibly not REST compliant?)
        tags_new = ['tag3', 'tag4']
        response = self.post_finding_tags_api(finding_id, tags_new)
        tags_merged = list(set(tags) | set(tags_new))
        self.assertEqual(len(tags_merged), len(response.get('tags')))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_finding_post_tags_overlap(self):
        # create finding
        tags = ['tag1', 'tag2']
        finding_id = self.create_finding_with_tags(tags)

        # post tags. POST will ADD tags to existing tags (which is possibly not REST compliant?)
        tags_new = ['tag2', 'tag3']
        response = self.post_finding_tags_api(finding_id, tags_new)
        tags_merged = list(set(tags) | set(tags_new))
        self.assertEqual(len(tags_merged), len(response.get('tags')))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_finding_put_remove_tags(self):
        # create finding
        tags = ['tag1', 'tag2']
        finding_id = self.create_finding_with_tags(tags)

        # post tags. PUT will remove any tags that exist
        tags_remove = ['tag1']
        response = self.put_finding_remove_tags_api(finding_id, tags_remove)

        # for some reason this method returns just a message, not the remaining tags
        self.assertEquals(response['success'], 'Tag(s) Removed')

        # retrieve finding and check
        tags_merged = list(set(tags) - set(tags_remove))
        response = self.get_finding_tags_api(finding_id)
        self.assertEqual(len(tags_merged), len(response.get('tags')))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_finding_put_remove_tags_all(self):
        # create finding
        tags = ['tag1', 'tag2']
        finding_id = self.create_finding_with_tags(tags)

        # post tags. PUT will remove any tags that exist
        tags_remove = tags
        response = self.put_finding_remove_tags_api(finding_id, tags_remove)

        # for some reason this method returns just a message, not the remaining tags
        self.assertEquals(response['success'], 'Tag(s) Removed')

        # retrieve finding and check
        tags_merged = list(set(tags) - set(tags_remove))
        response = self.get_finding_tags_api(finding_id)
        self.assertEqual(len(tags_merged), len(response.get('tags')))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_finding_put_remove_tags_non_existent(self):
        # create finding
        tags = ['tag1', 'tag2']
        finding_id = self.create_finding_with_tags(tags)

        # post tags. PUT will throw an error on non-existent tag to be removed (which is maybe not what we want?)
        tags_remove = ['tag5']
        response = self.put_finding_remove_tags_api(finding_id, tags_remove, expected_response_status_code=400)

        # for some reason this method returns just a message, not the remaining tags
        self.assertEquals(response['error'], '\'tag5\' is not a valid tag in list')

        # retrieve finding and check
        tags_merged = list(set(tags) - set(tags_remove))
        response = self.get_finding_tags_api(finding_id)
        self.assertEqual(len(tags_merged), len(response.get('tags')))
        for tag in tags_merged:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_finding_patch_remove_tags(self):
        # has same logic as PUT
        return self.test_finding_put_remove_tags()

    def test_finding_patch_remove_tags_all(self):
        return self.test_finding_put_remove_tags_all()

    def test_finding_patch_remove_tags_non_existent(self):
        return self.test_finding_put_remove_tags_non_existent()

    def test_finding_create_tags_with_commas(self):
        tags = ['one,two']
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        # via API the tag gets split into two tags (via the UI no splitting happens)
        self.assertEqual(2, len(response.get('tags')))
        self.assertTrue('one' in response['tags'])
        self.assertTrue('two' in response['tags'])

    def test_finding_create_tags_with_commas_quoted(self):
        tags = ['"one,two"']
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        # no splitting due to quotes
        self.assertEqual(len(tags), len(response.get('tags', None)))
        for tag in tags:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag.strip('\"') in response['tags'])

    def test_finding_create_tags_with_spaces(self):
        tags = ['one two']
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        # via API the tag gets split into two tags (via the UI no splitting happens)
        self.assertEqual(2, len(response.get('tags')))
        self.assertTrue('one' in response['tags'])
        self.assertTrue('two' in response['tags'])
        # finding.tags: [<Tag: one>, <Tag: two>]

    def test_finding_create_tags_with_spaces_quoted(self):
        tags = ['"one two"']
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        # no splitting due to quotes
        self.assertEqual(len(tags), len(response.get('tags', None)))
        for tag in tags:
            logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag.strip('\"') in response['tags'])

        # finding.tags: <QuerySet [<Tag: one two>]>

    def test_finding_create_tags_with_slashes(self):
        tags = ['a/b/c']
        finding_id = self.create_finding_with_tags(tags)
        response = self.get_finding_tags_api(finding_id)

        self.assertEqual(len(tags), len(response.get('tags', None)))
        for tag in tags:
            # logger.debug('looking for tag %s in tag list %s', tag, response['tags'])
            self.assertTrue(tag in response['tags'])

    def test_import_and_reimport_with_tags(self):
        tags = ['tag1', 'tag2']
        import0 = self.import_scan_with_params(self.zap_sample5_filename, tags=tags)
        test_id = import0['test']

        response = self.get_test_api(test_id)

        self.assertEqual(len(tags), len(response.get('tags')))
        for tag in tags:
            self.assertTrue(tag in response['tags'])

        # reimport, do not specify tags: should retain tags
        reimport = self.reimport_scan_with_params(test_id, self.zap_sample5_filename)
        self.assertEqual(len(tags), len(response.get('tags')))
        for tag in tags:
            self.assertTrue(tag in response['tags'])

        # reimport, specify tags others: currently reimport doesn't do anything with tags param and silently ignores them
        reimport = self.reimport_scan_with_params(test_id, self.zap_sample5_filename, tags=['tag3', 'tag4'])
        self.assertEqual(len(tags), len(response.get('tags')))
        for tag in tags:
            self.assertTrue(tag in response['tags'])
