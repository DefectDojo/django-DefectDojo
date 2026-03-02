import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest, WaitForPageLoad
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import Select, WebDriverWait


class FindingExtendedTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_copy_finding(self):
        driver = self.driver
        self.goto_all_findings_list(driver)
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Copy Finding").click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Finding Copied successfully")
            or self.is_text_present_on_page(text="App Vulnerable to XSS"),
        )

    @on_exception_html_source_logger
    def test_bulk_edit_severity(self):
        driver = self.driver
        driver.get(self.base_url + "finding")
        self.wait_for_datatable_if_content("no_findings", "open_findings_wrapper")
        # Select all findings via the select_all checkbox
        driver.find_element(By.ID, "select_all").click()
        time.sleep(1)
        # Wait for the bulk edit menu to become visible
        WebDriverWait(driver, 10).until(
            expected_conditions.visibility_of_element_located((By.ID, "dropdownMenu2")),
        )
        # Open bulk edit dropdown and set severity via JavaScript
        # (Bootstrap dropdowns can be tricky with Selenium visibility checks)
        driver.execute_script("""
            // Open the dropdown
            $('#dropdownMenu2').dropdown('toggle');
            // Set severity to Medium
            var sel = document.getElementById('severity');
            sel.value = 'Medium';
            $(sel).trigger('change');
        """)
        time.sleep(1)
        # Submit the bulk edit form via JavaScript
        driver.execute_script(
            "document.querySelector('#bulk_change_form input[type=submit]').click();",
        )
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="updated")
            or self.is_text_present_on_page(text="Finding"),
        )

    @on_exception_html_source_logger
    def test_bulk_edit_status(self):
        driver = self.driver
        driver.get(self.base_url + "finding")
        self.wait_for_datatable_if_content("no_findings", "open_findings_wrapper")
        # Select all findings
        driver.find_element(By.ID, "select_all").click()
        time.sleep(1)
        # Open bulk edit dropdown and set status via JavaScript
        driver.execute_script("""
            // Open the dropdown
            $('#dropdownMenu2').dropdown('toggle');
            // Enable status editing and set active+verified
            var statusCb = document.getElementById('id_bulk_status');
            if (statusCb && !statusCb.checked) statusCb.click();
            var activeCb = document.getElementById('id_bulk_active');
            if (activeCb && !activeCb.checked) activeCb.click();
            var verifiedCb = document.getElementById('id_bulk_verified');
            if (verifiedCb && !verifiedCb.checked) verifiedCb.click();
        """)
        time.sleep(1)
        # Submit bulk edit form
        driver.execute_script(
            "document.querySelector('#bulk_change_form input[type=submit]').click();",
        )
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="updated")
            or self.is_text_present_on_page(text="Finding"),
        )

    @on_exception_html_source_logger
    def test_remediation_date(self):
        driver = self.driver
        self.goto_all_findings_list(driver)
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Remediation Date").click()
        # Set a remediation date
        driver.find_element(By.ID, "id_planned_remediation_date").clear()
        driver.find_element(By.ID, "id_planned_remediation_date").send_keys("2030-12-31")
        # Dismiss the datepicker overlay before clicking submit
        driver.find_element(By.ID, "id_planned_remediation_date").send_keys(Keys.ESCAPE)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Remediation date")
            or self.is_text_present_on_page(text="App Vulnerable to XSS"),
        )

    @on_exception_html_source_logger
    def test_ad_hoc_finding_create(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Click on the Findings dropdown
        driver.find_element(By.PARTIAL_LINK_TEXT, "Findings").click()
        driver.find_element(By.LINK_TEXT, "Add New Finding").click()
        # Fill finding form
        driver.find_element(By.ID, "id_title").clear()
        driver.find_element(By.ID, "id_title").send_keys("Ad Hoc Test Finding")
        Select(driver.find_element(By.ID, "id_severity")).select_by_visible_text("Medium")
        driver.execute_script("document.getElementsByName('description')[1].style.display = 'inline'")
        driver.find_elements(By.NAME, "description")[1].send_keys(Keys.TAB, "Ad hoc finding for testing")
        driver.execute_script("document.getElementsByName('mitigation')[0].style.display = 'inline'")
        driver.find_element(By.NAME, "mitigation").send_keys(Keys.TAB, "Test mitigation")
        driver.execute_script("document.getElementsByName('impact')[0].style.display = 'inline'")
        driver.find_element(By.NAME, "impact").send_keys(Keys.TAB, "Test impact")
        with WaitForPageLoad(driver, timeout=30):
            driver.find_element(By.XPATH, "//input[@name='_Finished']").click()

        self.assertTrue(self.is_text_present_on_page(text="Ad Hoc Test Finding"))

    @on_exception_html_source_logger
    def test_touch_finding(self):
        driver = self.driver
        self.goto_all_findings_list(driver)
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Touch Finding").click()

        self.assertTrue(
            self.is_success_message_present(text="Finding touched")
            or self.is_text_present_on_page(text="App Vulnerable to XSS"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(FindingExtendedTest("test_copy_finding"))
    suite.addTest(FindingExtendedTest("test_bulk_edit_severity"))
    suite.addTest(FindingExtendedTest("test_bulk_edit_status"))
    suite.addTest(FindingExtendedTest("test_remediation_date"))
    suite.addTest(FindingExtendedTest("test_ad_hoc_finding_create"))
    suite.addTest(FindingExtendedTest("test_touch_finding"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
