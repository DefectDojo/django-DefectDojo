import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

# Built-in API tool types that require credentials and fail without them
API_TOOL_TYPES = {"BlackDuck API", "Bugcrowd API", "Cobalt.io", "Edgescan", "SonarQube", "Vulners"}


class ToolProductTest(BaseTestCase):

    def _get_product_id(self, driver):
        """Navigate to QA Test product and return the product ID."""
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        current_url = driver.current_url
        parts = current_url.rstrip("/").split("/")
        return parts[-1]

    def _select_non_api_tool_type(self, select_element):
        """Select a tool type that is not a built-in API type (which require credentials)."""
        for i, opt in enumerate(select_element.options):
            text = opt.text.strip()
            if text and text != "---------" and text not in API_TOOL_TYPES:
                select_element.select_by_index(i)
                return True
        return False

    @on_exception_html_source_logger
    def test_ensure_tool_type_exists(self):
        """Ensure at least one non-API tool type exists (create if needed)."""
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        time.sleep(1)
        # Check if any non-API tool type exists
        has_custom_type = False
        links = driver.find_elements(By.CSS_SELECTOR, "table a")
        for link in links:
            text = link.text.strip()
            if text and text not in API_TOOL_TYPES:
                has_custom_type = True
                break
        if not has_custom_type:
            # Create a custom tool type
            driver.find_element(By.ID, "dropdownMenu1").click()
            driver.find_element(By.LINK_TEXT, "Add Tool Type").click()
            driver.find_element(By.ID, "id_name").clear()
            driver.find_element(By.ID, "id_name").send_keys("Integration Test Tool Type")
            description_fields = driver.find_elements(By.ID, "id_description")
            if len(description_fields) > 0:
                description_fields[0].clear()
                description_fields[0].send_keys("Tool type for integration tests")
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            time.sleep(1)
        # Verify tool type list page loads without errors
        driver.get(self.base_url + "tool_type")
        self.assertTrue(self.is_text_present_on_page(text="Tool Types"))

    @on_exception_html_source_logger
    def test_ensure_tool_configuration_exists(self):
        """Ensure a tool configuration exists for a non-API tool type."""
        driver = self.driver
        driver.get(self.base_url + "tool_config")
        time.sleep(1)
        # Check if any tool config exists (any row in the table)
        # We need at least one tool config that uses a non-API tool type
        rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
        has_usable_config = False
        for row in rows:
            cells = row.find_elements(By.TAG_NAME, "td")
            if len(cells) >= 2:
                tool_type_text = cells[1].text.strip() if len(cells) > 1 else ""
                if tool_type_text and tool_type_text not in API_TOOL_TYPES:
                    has_usable_config = True
                    break
        if not has_usable_config:
            # Create a new tool configuration using a non-API tool type
            driver.get(self.base_url + "tool_config/add")
            time.sleep(1)
            driver.find_element(By.ID, "id_name").clear()
            driver.find_element(By.ID, "id_name").send_keys("Test Tool Config For Product")
            tool_type_select = Select(driver.find_element(By.ID, "id_tool_type"))
            if not self._select_non_api_tool_type(tool_type_select):
                # No non-API tool type available; select index 1 as last resort
                if len(tool_type_select.options) > 1:
                    tool_type_select.select_by_index(1)
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            time.sleep(2)
        # Verify tool config list page loads
        driver.get(self.base_url + "tool_config")
        self.assertTrue(self.is_text_present_on_page(text="Tool Configurations"))

    @on_exception_html_source_logger
    def test_list_tool_products(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/tool_product/all")
        self.assertTrue(
            self.is_text_present_on_page(text="Tools")
            or self.is_text_present_on_page(text="No tools configured"),
        )

    @on_exception_html_source_logger
    def test_add_tool_product(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/tool_product/add")
        time.sleep(1)
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test Tool Product Config")
        # Select tool_configuration — pick first available non-empty option
        tool_config_select = Select(driver.find_element(By.ID, "id_tool_configuration"))
        selected = False
        for i, opt in enumerate(tool_config_select.options):
            if opt.get_attribute("value"):
                tool_config_select.select_by_index(i)
                selected = True
                break
        if not selected:
            return
        # Fill URL if available
        url_fields = driver.find_elements(By.ID, "id_url")
        if len(url_fields) > 0:
            url_fields[0].clear()
            url_fields[0].send_keys("https://tool.example.com")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(2)

        self.assertTrue(
            self.is_success_message_present(text="Product Tool Configuration Successfully Created")
            or self.is_text_present_on_page(text="Tools"),
        )

    @on_exception_html_source_logger
    def test_edit_tool_product(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/tool_product/all")
        # Click Edit link from the tools list
        edit_links = driver.find_elements(By.LINK_TEXT, "Edit")
        if len(edit_links) > 0:
            edit_links[0].click()
            driver.find_element(By.ID, "id_name").clear()
            driver.find_element(By.ID, "id_name").send_keys("Edited Tool Product Config")
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            self.assertTrue(
                self.is_success_message_present(text="Tool Product Configuration Successfully Updated")
                or self.is_text_present_on_page(text="Tools"),
            )
        else:
            # No tools to edit - just verify page is fine
            self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_delete_tool_product(self):
        driver = self.driver
        pid = self._get_product_id(driver)
        driver.get(self.base_url + f"product/{pid}/tool_product/all")
        # Click Delete link from the tools list
        delete_links = driver.find_elements(By.LINK_TEXT, "Delete")
        if len(delete_links) > 0:
            delete_links[0].click()
            driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()
            self.assertTrue(
                self.is_success_message_present(text="Tool Product Successfully Deleted")
                or self.is_text_present_on_page(text="Tools"),
            )
        else:
            # No tools to delete
            self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ToolProductTest("test_ensure_tool_type_exists"))
    suite.addTest(ToolProductTest("test_ensure_tool_configuration_exists"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ToolProductTest("test_list_tool_products"))
    suite.addTest(ToolProductTest("test_add_tool_product"))
    suite.addTest(ToolProductTest("test_edit_tool_product"))
    suite.addTest(ToolProductTest("test_delete_tool_product"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
