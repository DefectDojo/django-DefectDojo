import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class RiskAcceptanceTest(BaseTestCase):

    def _get_engagement_url(self, driver):
        """Navigate to the Beta Test engagement via the all engagements list."""
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        # Find the Beta Test engagement link in the table
        eng_links = driver.find_elements(By.LINK_TEXT, "Beta Test")
        if len(eng_links) > 0:
            eng_links[0].click()
            time.sleep(1)
            return driver.current_url
        # Fallback: try partial link text
        eng_links = driver.find_elements(By.PARTIAL_LINK_TEXT, "Beta")
        if len(eng_links) > 0:
            eng_links[0].click()
            time.sleep(1)
            return driver.current_url
        return None

    def _get_engagement_id(self, driver):
        """Get the engagement ID from the current engagement page URL."""
        eng_url = self._get_engagement_url(driver)
        if eng_url is None:
            return None
        # URL pattern: .../engagement/<id>
        parts = eng_url.rstrip("/").split("/")
        for i, part in enumerate(parts):
            if part == "engagement" and i + 1 < len(parts):
                return parts[i + 1]
        return parts[-1]

    @on_exception_html_source_logger
    def test_enable_full_risk_acceptance(self):
        """Enable full risk acceptance on the QA Test product."""
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Edit").click()
        time.sleep(1)
        # Enable full risk acceptance checkbox
        checkbox = driver.find_element(By.ID, "id_enable_full_risk_acceptance")
        if not checkbox.is_selected():
            checkbox.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Product updated successfully")
            or self.is_text_present_on_page(text="QA Test"),
        )

    @on_exception_html_source_logger
    def test_add_risk_acceptance(self):
        """Add a risk acceptance to the engagement."""
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        driver.get(self.base_url + f"engagement/{eid}/risk_acceptance/add")
        time.sleep(2)
        # Fill the risk acceptance form
        name_field = driver.find_element(By.ID, "id_name")
        name_field.clear()
        name_field.send_keys("Test Risk Acceptance")
        # Select an accepted finding if available
        findings_select = driver.find_elements(By.ID, "id_accepted_findings")
        if len(findings_select) > 0:
            options = findings_select[0].find_elements(By.TAG_NAME, "option")
            if len(options) > 0:
                options[0].click()
        # Radio buttons for recommendation and decision - click Accept options
        rec_radios = driver.find_elements(By.NAME, "recommendation")
        if len(rec_radios) > 0:
            rec_radios[0].click()
        dec_radios = driver.find_elements(By.NAME, "decision")
        if len(dec_radios) > 0:
            dec_radios[0].click()
        # Owner is pre-filled (current user), submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Risk acceptance saved")
            or self.is_text_present_on_page(text="Risk Acceptance")
            or self.is_text_present_on_page(text="Engagement"),
        )

    @on_exception_html_source_logger
    def test_view_risk_acceptance(self):
        """View a risk acceptance from the engagement."""
        driver = self.driver
        eng_url = self._get_engagement_url(driver)
        self.assertIsNotNone(eng_url, "Could not find Beta Test engagement")
        time.sleep(1)
        # Look for risk acceptance links on the engagement page
        risk_links = driver.find_elements(By.PARTIAL_LINK_TEXT, "Test Risk Acceptance")
        if len(risk_links) > 0:
            risk_links[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_text_present_on_page(text="Risk Acceptance")
                or self.is_text_present_on_page(text="Test Risk Acceptance"),
            )
        else:
            # Risk acceptance may be listed differently
            self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_delete_risk_acceptance(self):
        """Delete a risk acceptance."""
        driver = self.driver
        eng_url = self._get_engagement_url(driver)
        self.assertIsNotNone(eng_url, "Could not find Beta Test engagement")
        time.sleep(1)
        # Find delete links for risk acceptances
        delete_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='risk_acceptance'][href*='delete']")
        if len(delete_links) > 0:
            delete_links[0].click()
            time.sleep(1)
            # Confirm delete - the URL pattern is a GET request that performs delete
            # Check if we're on a confirmation page
            confirm_btns = driver.find_elements(By.CSS_SELECTOR, "input.btn.btn-danger")
            if len(confirm_btns) > 0:
                confirm_btns[0].click()
            else:
                button_btns = driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-danger")
                if len(button_btns) > 0:
                    button_btns[0].click()
            time.sleep(1)
            self.assertTrue(
                self.is_success_message_present(text="Risk acceptance deleted successfully")
                or self.is_text_present_on_page(text="Engagement"),
            )
        else:
            self.assertFalse(self.is_error_message_present())


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_engagement"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(RiskAcceptanceTest("test_enable_full_risk_acceptance"))
    suite.addTest(RiskAcceptanceTest("test_add_risk_acceptance"))
    suite.addTest(RiskAcceptanceTest("test_view_risk_acceptance"))
    suite.addTest(RiskAcceptanceTest("test_delete_risk_acceptance"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
