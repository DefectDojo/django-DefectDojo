import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class ObjectTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_enable_product_tracking_files(self):
        """Enable product tracking files in system settings."""
        driver = self.driver
        driver.get(self.base_url + "system_settings")
        tracking_checkbox = driver.find_element(By.ID, "id_enable_product_tracking_files")
        if not tracking_checkbox.is_selected():
            tracking_checkbox.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_view_objects_page_loads(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Get product ID from current URL
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"product/{pid}/object/view")
        self.assertTrue(
            self.is_text_present_on_page(text="Tracked Files")
            or self.is_text_present_on_page(text="Tracked"),
        )

    @on_exception_html_source_logger
    def test_add_object(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Get the product ID from current URL
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        pid = parts[-1]
        driver.get(self.base_url + f"product/{pid}/object/add")
        # Fill in object form
        path_fields = driver.find_elements(By.ID, "id_path")
        if len(path_fields) > 0:
            path_fields[0].clear()
            path_fields[0].send_keys("/test/path/to/file.py")
        folder_fields = driver.find_elements(By.ID, "id_folder")
        if len(folder_fields) > 0:
            folder_fields[0].clear()
            folder_fields[0].send_keys("/test/folder")
        artifact_fields = driver.find_elements(By.ID, "id_artifact")
        if len(artifact_fields) > 0:
            artifact_fields[0].clear()
            artifact_fields[0].send_keys("test-artifact")
        # Select review_status if available
        from selenium.webdriver.support.ui import Select
        review_fields = driver.find_elements(By.ID, "id_review_status")
        if len(review_fields) > 0:
            select = Select(review_fields[0])
            if len(select.options) > 1:
                select.select_by_index(1)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(
            self.is_success_message_present(text="added successfully")
            or self.is_text_present_on_page(text="Tracked Files"),
        )

def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ObjectTest("test_enable_product_tracking_files"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ObjectTest("test_view_objects_page_loads"))
    suite.addTest(ObjectTest("test_add_object"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
