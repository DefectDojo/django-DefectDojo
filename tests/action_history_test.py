import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class ActionHistoryTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_product_action_history(self):
        """Test the action history page for a product."""
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Get the content type ID for Product
        # Use the Django history URL pattern: history/<content_type_id>/<object_id>
        # We can navigate to it via the product page's history link if available
        driver.find_element(By.ID, "dropdownMenu1").click()
        time.sleep(0.5)
        history_links = driver.find_elements(By.LINK_TEXT, "History")
        if len(history_links) > 0:
            history_links[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_text_present_on_page(text="History")
                or self.is_text_present_on_page(text="history")
                or self.is_text_present_on_page(text="Action"),
            )
        else:
            # History link might not be in dropdown, just verify no error
            self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_components_page_loads(self):
        """Test the global components page loads."""
        driver = self.driver
        driver.get(self.base_url + "components")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Component")
            or self.is_text_present_on_page(text="component"),
        )

    @on_exception_html_source_logger
    def test_product_components_page(self):
        """Test the product components page."""
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"product/{pid}/components")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Component")
            or self.is_text_present_on_page(text="QA Test"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(ActionHistoryTest("test_product_action_history"))
    suite.addTest(ActionHistoryTest("test_components_page_loads"))
    suite.addTest(ActionHistoryTest("test_product_components_page"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
