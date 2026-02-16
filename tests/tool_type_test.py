import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger
from selenium.webdriver.common.by import By


class ToolTypeTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_list_tool_types(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_add_tool_type(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Add Tool Type").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test Tool Type")
        description_fields = driver.find_elements(By.ID, "id_description")
        if len(description_fields) > 0:
            description_fields[0].clear()
            description_fields[0].send_keys("A test tool type for integration testing")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Tool Type Configuration Successfully Created")
            or self.is_text_present_on_page(text="Test Tool Type"),
        )

    @on_exception_html_source_logger
    def test_edit_tool_type(self):
        driver = self.driver
        driver.get(self.base_url + "tool_type")
        driver.find_element(By.LINK_TEXT, "Test Tool Type").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited Test Tool Type")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Tool Type Configuration Successfully Updated")
            or self.is_text_present_on_page(text="Edited Test Tool Type"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(ToolTypeTest("test_list_tool_types"))
    suite.addTest(ToolTypeTest("test_add_tool_type"))
    suite.addTest(ToolTypeTest("test_edit_tool_type"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
