from .dojo_test_case import DojoTestCase
from dojo.search.views import parse_search_query


class TestSearch(DojoTestCase):
    def test_parse_query(self):

        operators, keywords = parse_search_query("some keywords")
        self.assertEqual(len(operators), 0)
        self.assertEqual(len(keywords), 2)
        self.assertEqual(keywords[0], "some")
        self.assertEqual(keywords[1], "keywords")

        operators, keywords = parse_search_query("some key-word")
        self.assertEqual(len(operators), 0)
        self.assertEqual(len(keywords), 2)
        self.assertEqual(keywords[0], "some")
        self.assertEqual(keywords[1], "key-word")

        operators, keywords = parse_search_query('keyword with "space inside"')
        self.assertEqual(len(operators), 0)
        self.assertEqual(len(keywords), 3)
        self.assertEqual(keywords[0], "keyword")
        self.assertEqual(keywords[1], "with")
        self.assertEqual(keywords[2], "space inside")

        operators, keywords = parse_search_query("tag:anchore word tags:php")
        # print(operators)
        # print(keywords)

        self.assertEqual(len(operators), 2)
        self.assertEqual(len(operators["tag"]), 1)
        self.assertEqual(len(operators["tags"]), 1)
        self.assertEqual(operators["tag"][0], "anchore")
        self.assertEqual(operators["tags"][0], "php")
        self.assertEqual(len(keywords), 1)
        self.assertEqual(keywords[0], "word")

        operators, keywords = parse_search_query("tags:php,magento")
        self.assertEqual(len(operators), 1)
        self.assertEqual(len(operators["tags"]), 1)
        self.assertEqual(operators["tags"][0], "php,magento")
        self.assertEqual(len(keywords), 0)

        operators, keywords = parse_search_query('tags:"php, magento"')
        self.assertEqual(len(operators), 1)
        self.assertEqual(len(operators["tags"]), 1)
        self.assertEqual(operators["tags"][0], "php, magento")
        self.assertEqual(len(keywords), 0)

        operators, keywords = parse_search_query('tags:anchore some "space inside"')
        self.assertEqual(len(operators), 1)
        self.assertEqual(len(operators["tags"]), 1)
        self.assertEqual(operators["tags"][0], "anchore")
        self.assertEqual(len(keywords), 2)
        self.assertEqual(keywords[0], "some")
        self.assertEqual(keywords[1], "space inside")

        operators, keywords = parse_search_query(
            "tags:anchore cve:CVE-2020-1234 jquery tags:beer"
        )
        self.assertEqual(len(operators), 2)
        self.assertEqual(len(operators["tags"]), 2)
        self.assertEqual(operators["tags"][0], "anchore")
        self.assertEqual(operators["tags"][1], "beer")
        self.assertEqual(len(operators["cve"]), 1)
        self.assertEqual(operators["cve"][0], "CVE-2020-1234")
        self.assertEqual(len(keywords), 1)
        self.assertEqual(keywords[0], "jquery")
