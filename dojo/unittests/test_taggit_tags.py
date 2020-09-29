from django.test import TestCase
from dojo.models import Product


class TaggitTests(TestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self, *args, **kwargs):
        pass

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
