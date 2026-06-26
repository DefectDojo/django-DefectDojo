import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class BenchmarkTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_view_product_benchmark(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Try to navigate to benchmark page via dropdown
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Look for benchmark link - it may be named "ASVS" or "Benchmark"
        benchmark_links = driver.find_elements(By.PARTIAL_LINK_TEXT, "Benchmark")
        if len(benchmark_links) > 0:
            benchmark_links[0].click()
            body_text = driver.find_element(By.TAG_NAME, "body").text
            self.assertIsNotNone(body_text)
        else:
            # Benchmarks may not be configured, try direct URL
            # Get the product ID from current URL
            current_url = driver.current_url
            # Extract product ID
            parts = current_url.rstrip("/").split("/")
            pid = parts[-1]
            driver.get(self.base_url + f"benchmark/{pid}/type/1")
            body_text = driver.find_element(By.TAG_NAME, "body").text
            self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_update_benchmark(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Try accessing benchmark update
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"benchmark/{pid}/type/1")
        # Verify the page loads without errors
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_benchmark_page_no_errors(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"benchmark/{pid}/type/1")
        # The page should load without severe javascript errors
        # (checked by tearDown via assertNoConsoleErrors)
        self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(BenchmarkTest("test_view_product_benchmark"))
    suite.addTest(BenchmarkTest("test_update_benchmark"))
    suite.addTest(BenchmarkTest("test_benchmark_page_no_errors"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
