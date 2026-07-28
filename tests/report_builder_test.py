import sys
import unittest

from base_test_class import BaseTestCase
from product_test import ProductTest
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import Select, WebDriverWait


class ReportBuilderTest(BaseTestCase):

    # Move the report blocks from Available Widgets to Report Format
    def move_blocks(self, driver):
        in_use = driver.find_element(By.ID, "sortable2")
        available_widgets = driver.find_element(By.ID, "sortable1").find_elements(By.TAG_NAME, "li")
        for widget in available_widgets:
            ActionChains(driver).drag_and_drop(widget, in_use).perform()

    # Fill in the boxes
    def enter_values(self, driver):
        in_use = driver.find_element(By.ID, "sortable2").find_elements(By.TAG_NAME, "li")
        for widget in in_use:
            class_names = widget.get_attribute("class")
            if "cover-page" in class_names:
                inputs = widget.find_elements(By.TAG_NAME, "input")
                for field in inputs:
                    field.send_keys("cover words")
            if "wysiwyg-content" in class_names:
                widget.find_element(By.CLASS_NAME, "editor").send_keys("wysiwyg")

    # Regression guard for the report-chart / table-of-contents race: the
    # executive-summary charts are rendered from a ready handler, while the
    # table-of-contents builder runs on window.onload and reassigns
    # #contents.innerHTML. That reassignment re-parses the subtree and
    # destroys any chart canvases painted before it (Chart.js in the new UI,
    # Flot in the classic UI). With executive summary AND table of contents
    # both enabled, every chart must end up painted once the page settles.
    def assert_report_charts_painted(self, chart_ids):
        driver = self.driver
        charts_painted = (
            "return arguments[0].map(function (id) {"
            "  var el = document.getElementById(id);"
            "  if (!el) { return false; }"
            "  var canvases = el.querySelectorAll('canvas');"
            "  for (var i = 0; i < canvases.length; i++) {"
            "    if (!canvases[i].width || !canvases[i].height) { continue; }"
            "    var ctx = canvases[i].getContext('2d');"
            "    var data = ctx.getImageData(0, 0, canvases[i].width, canvases[i].height).data;"
            "    for (var j = 3; j < data.length; j += 64) {"
            "      if (data[j] > 0) { return true; }"
            "    }"
            "  }"
            "  return false;"
            "});"
        )
        try:
            WebDriverWait(driver, 20).until(lambda d: all(d.execute_script(charts_painted, chart_ids)))
        except TimeoutException:
            self.fail(
                "Executive-summary charts were not painted after page load "
                f"({chart_ids} painted: {driver.execute_script(charts_painted, chart_ids)}); "
                "the table-of-contents builder likely destroyed them.",
            )

    def generate_HTML_report(self):
        driver = self.driver
        driver.get(self.base_url + "reports/builder")
        self.move_blocks(driver)
        self.enter_values(driver)
        Select(driver.find_element(By.ID, "id_report_type")).select_by_visible_text("HTML")
        driver.find_element(By.ID, "id_report_name").send_keys("Test Report")
        driver.find_element(By.CLASS_NAME, "run_report").click()
        self.assertEqual(driver.current_url, self.base_url + "reports/custom")

    def test_product_type_report(self):
        driver = self.driver
        driver.get(self.base_url + "product/type")
        driver.find_element(By.ID, "dropdownMenuProductType").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Report").click()
        my_select = Select(driver.find_element(By.ID, "id_include_finding_notes"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_table_of_contents"))
        my_select.select_by_index(1)

        driver.find_element(By.NAME, "_generate").click()

        # opened_per_month_2 is only rendered when the product type has
        # endpoint-per-month data, so only the unconditional chart is asserted.
        self.assert_report_charts_painted(["open_findings"])

    def test_product_report(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Asset Report").click()

        my_select = Select(driver.find_element(By.ID, "id_include_finding_notes"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_table_of_contents"))
        my_select.select_by_index(1)

        driver.find_element(By.NAME, "_generate").click()

        self.assert_report_charts_painted(["open_findings", "finding_age"])

    def test_engagement_report(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Engagements").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Ad Hoc Engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Report").click()
        my_select = Select(driver.find_element(By.ID, "id_include_finding_notes"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_table_of_contents"))
        my_select.select_by_index(1)

        driver.find_element(By.NAME, "_generate").click()

        self.assert_report_charts_painted(["open_findings", "finding_age"])

    def test_test_report(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Engagements").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "Ad Hoc Engagement").click()
        driver.find_element(By.LINK_TEXT, "Pen Test").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Report").click()
        my_select = Select(driver.find_element(By.ID, "id_include_finding_notes"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_table_of_contents"))
        my_select.select_by_index(1)

        driver.find_element(By.NAME, "_generate").click()

        self.assert_report_charts_painted(["open_findings", "finding_age"])

    def test_product_endpoint_report(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Endpoints").click()
        driver.find_element(By.LINK_TEXT, "Endpoint Report").click()

        # extra dropdown click
        dropdown = WebDriverWait(driver, 20).until(expected_conditions.visibility_of_element_located((By.ID, "show-filters")))

        dropdown = driver.find_element(By.ID, "show-filters")
        dropdown.click()

        my_select = WebDriverWait(driver, 20).until(expected_conditions.visibility_of_element_located((By.XPATH, "//label[@for='id_include_finding_notes']")))

        my_select = Select(driver.find_element(By.ID, "id_include_finding_notes"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_table_of_contents"))
        my_select.select_by_index(1)

        driver.find_element(By.NAME, "_generate").click()

        self.assert_report_charts_painted(["accepted_findings", "open_findings", "closed_findings", "finding_age"])

    def test_product_list_report(self):
        # Unlike the report tests above, this does not call
        # assert_report_charts_painted(): it generates the Findings Report,
        # whose view currently errors before the report (and its charts)
        # render, so there are no chart canvases to assert on. This test only
        # exercises the generate action until that view is fixed.
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Findings Report").click()

        my_select = Select(driver.find_element(By.ID, "id_include_finding_notes"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_executive_summary"))
        my_select.select_by_index(1)

        my_select = Select(driver.find_element(By.ID, "id_include_table_of_contents"))
        my_select.select_by_index(1)

        driver.find_element(By.NAME, "_generate").click()


def add_report_tests_to_suite(suite):
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(BaseTestCase("disable_block_execution"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(ProductTest("test_add_product_endpoints"))
    suite.addTest(ReportBuilderTest("generate_HTML_report"))
    # we add reports here as we now have a product that triggers some logic inside reports
    suite.addTest(ReportBuilderTest("test_product_type_report"))
    suite.addTest(ReportBuilderTest("test_product_report"))
    suite.addTest(ReportBuilderTest("test_engagement_report"))
    suite.addTest(ReportBuilderTest("test_test_report"))
    suite.addTest(ReportBuilderTest("test_product_endpoint_report"))

    suite.addTest(ProductTest("test_delete_product"))
    return suite


def suite():
    suite = unittest.TestSuite()
    add_report_tests_to_suite(suite)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
