from django.urls import reverse

from dojo.models import Finding
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class FindingMarkdownRenderingTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_finding_description_renders_markdown_outside_pre(self):
        Finding.objects.filter(pk=2).update(description=(
            "# Finding overview\n\n"
            "First line\nSecond line\n\n"
            "| Key | Value |\n| --- | --- |\n| Example | Detail |\n\n"
            "- First item\n- Second item\n\n"
            "```\nexample command\n```"
        ))
        self.client.force_login(self.get_test_admin())
        response = self.client.get(reverse("view_finding", args=(2,)))
        self.assertEqual(response.status_code, 200)

        html = response.content.decode()
        self.assertNotRegex(html, r"<pre\b[^>]*>\s*<h1\b[^>]*>Finding overview</h1>")
        self.assertIn('<h1 id="finding-overview">Finding overview</h1>', html)
        self.assertRegex(html, r"<p>First line<br\s*/?>\s*Second line</p>")
        self.assertRegex(html, r"<tr>\s*<td>Example</td>\s*<td>Detail</td>\s*</tr>")
        self.assertRegex(html, r"<ul>\s*<li>First item</li>\s*<li>Second item</li>\s*</ul>")
        self.assertRegex(html, r"<pre\b[^>]*>(?:<span></span>)?<code>example command\s*</code></pre>")
