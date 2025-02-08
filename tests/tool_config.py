import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select


class ToolConfigTest(BaseTestCase):

    def goto_add_api_scan_configuration(self, driver):
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add Scan API Configuration").click()
        return driver

    @on_exception_html_source_logger
    def test_list_api_scan_configuration_tt_and_tc_missing(self):
        driver = self.driver
        # Navigate to the 'Add test API Scan Configuration' page
        self.goto_add_api_scan_configuration(driver)
        # Check that there is no "Edgescan" definition
        self.assertEqual(driver.find_element(By.ID, "link_tt_edgescan_scan").text, "Parser Edgescan Scan requires created tool type Edgescan.")

    @on_exception_html_source_logger
    def test_setup_tt_via_api_scan_configuration(self):
        driver = self.driver
        # Navigate to the 'Add test API Scan Configuration' page
        self.goto_add_api_scan_configuration(driver)
        # Follow instuctions to create ToolType
        driver.find_element(By.ID, "link_tt_edgescan_scan").click()
        # Check if form is prefieled
        self.assertEqual(driver.find_element(By.ID, "id_name").get_attribute("value"), "Edgescan")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Tool Type Configuration Successfully Created."))
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_list_api_scan_configuration_tt_ready_tc_missing(self):
        driver = self.driver
        # Navigate to the 'Add test API Scan Configuration' page
        self.goto_add_api_scan_configuration(driver)
        # Check that there is no "Edgescan" definition
        self.assertEqual(driver.find_element(By.ID, "link_tc_edgescan_scan").text, "Tool type Edgescan exists however parser Edgescan Scan requires at least one tool configuration.")

    @on_exception_html_source_logger
    def test_setup_tc_via_api_scan_configuration(self):
        driver = self.driver
        # Navigate to the 'Add test API Scan Configuration' page
        self.goto_add_api_scan_configuration(driver)
        # Follow instuctions to create ToolType
        driver.find_element(By.ID, "link_tc_edgescan_scan").click()
        # Check if ToolType is selected
        self.assertTrue(driver.find_element(By.XPATH, "//select[@id='id_tool_type']/option[contains(text(),'Edgescan')]").is_selected())
        # Fill in th ToolConfig name
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("First Edgescan Tool Config")
        # Choose Ath type
        Select(driver.find_element(By.ID, "id_authentication_type")).select_by_visible_text("API Key")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Tool Configuration successfully updated."))
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_list_api_scan_configuration_tt_and_tc_ready(self):
        driver = self.driver
        # Navigate to the 'Add test API Scan Configuration' page
        self.goto_add_api_scan_configuration(driver)
        # Check that there is "Edgescan" helper
        self.assertFalse(self.is_element_by_id_present("link_tc_edgescan_scan"))
        self.assertFalse(self.is_element_by_id_present("link_tt_edgescan_scan"))

    @on_exception_html_source_logger
    def test_setup_api_scan_configuration(self):
        driver = self.driver
        # Navigate to the 'Add test API Scan Configuration' page
        self.goto_add_api_scan_configuration(driver)
        Select(driver.find_element(By.ID, "id_tool_configuration")).select_by_visible_text("First Edgescan Tool Config")
        # Fill in some service key
        driver.find_element(By.ID, "id_service_key_1").clear()
        driver.find_element(By.ID, "id_service_key_1").send_keys("service key")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="API Scan Configuration added successfully."))
        self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()

    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(BaseTestCase("disable_block_execution"))
    suite.addTest(ProductTest("test_create_product"))
    # Usable if instance doesn't autocreate all TTs
    # suite.addTest(ToolConfigTest('test_list_api_scan_configuration_tt_and_tc_missing'))
    # suite.addTest(ToolConfigTest('test_setup_tt_via_api_scan_configuration'))
    suite.addTest(ToolConfigTest("test_list_api_scan_configuration_tt_ready_tc_missing"))
    suite.addTest(ToolConfigTest("test_setup_tc_via_api_scan_configuration"))
    suite.addTest(ToolConfigTest("test_list_api_scan_configuration_tt_and_tc_ready"))
    suite.addTest(ToolConfigTest("test_setup_api_scan_configuration"))
    suite.addTest(ProductTest("test_delete_product"))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
