import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest


class MetricsExtendedTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_metrics_all_page(self):
        """Test the /metrics/all page loads."""
        driver = self.driver
        driver.get(self.base_url + "metrics/all")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Metrics")
            or self.is_text_present_on_page(text="Product Type"),
        )

    @on_exception_html_source_logger
    def test_metrics_organization_page(self):
        """Test the organization/product type metrics page."""
        driver = self.driver
        driver.get(self.base_url + "metrics/organization")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Metric")
            or self.is_text_present_on_page(text="Product Type"),
        )

    @on_exception_html_source_logger
    def test_engineer_metrics_page(self):
        """Test the engineer metrics page loads."""
        driver = self.driver
        driver.get(self.base_url + "metrics/engineer")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Metric")
            or self.is_text_present_on_page(text="Engineer"),
        )

    @on_exception_html_source_logger
    def test_simple_metrics_page(self):
        """Test the simple metrics page loads."""
        driver = self.driver
        driver.get(self.base_url + "metrics/simple")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Metric")
            or self.is_text_present_on_page(text="Finding"),
        )

    @on_exception_html_source_logger
    def test_product_type_counts_page(self):
        """Test the product type counts metrics page."""
        driver = self.driver
        driver.get(self.base_url + "metrics/product/type/counts")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Product Type")
            or self.is_text_present_on_page(text="Metric")
            or self.is_text_present_on_page(text="Count"),
        )

    @on_exception_html_source_logger
    def test_critical_product_metrics_page(self):
        """Test the critical product/asset metrics page."""
        driver = self.driver
        driver.get(self.base_url + "metrics")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Metric")
            or self.is_text_present_on_page(text="Product"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(MetricsExtendedTest("test_metrics_all_page"))
    suite.addTest(MetricsExtendedTest("test_metrics_organization_page"))
    suite.addTest(MetricsExtendedTest("test_engineer_metrics_page"))
    suite.addTest(MetricsExtendedTest("test_simple_metrics_page"))
    suite.addTest(MetricsExtendedTest("test_product_type_counts_page"))
    suite.addTest(MetricsExtendedTest("test_critical_product_metrics_page"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
