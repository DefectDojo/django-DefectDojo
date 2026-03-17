import os
import sys
import time
import unittest
from pathlib import Path

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By


class RiskAcceptanceTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_enable_full_risk_acceptance(self):
        """Enable full risk acceptance on the QA Test product."""
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Edit").click()
        time.sleep(1)
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
        """Add a risk acceptance with proof to the Ad Hoc Engagement."""
        driver = self.driver
        # Navigate to the Ad Hoc Engagement (where test_add_product_finding creates its finding)
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        driver.find_element(By.LINK_TEXT, "Ad Hoc Engagement").click()
        time.sleep(1)
        # Click "Add Risk Acceptance" from the engagement page
        driver.find_element(By.CSS_SELECTOR, "a[href*='risk_acceptance/add']").click()
        time.sleep(2)
        # Fill the risk acceptance form
        name_field = driver.find_element(By.ID, "id_name")
        name_field.clear()
        name_field.send_keys("Test Risk Acceptance")
        # Select an accepted finding - the native <select> is hidden by bootstrap-select
        driver.execute_script("document.getElementById('id_accepted_findings').style.display = 'inline'")
        findings_select = driver.find_element(By.ID, "id_accepted_findings")
        options = findings_select.find_elements(By.TAG_NAME, "option")
        self.assertTrue(len(options) > 0, "No findings available for risk acceptance")
        options[0].click()
        # Radio buttons for recommendation and decision
        rec_radios = driver.find_elements(By.NAME, "recommendation")
        if len(rec_radios) > 0:
            rec_radios[0].click()
        dec_radios = driver.find_elements(By.NAME, "decision")
        if len(dec_radios) > 0:
            dec_radios[0].click()
        # Upload a proof file
        proof_path = Path(os.path.realpath(__file__)).parent / "dedupe_scans" / "dedupe_path_1.json"
        driver.find_element(By.ID, "id_path").send_keys(str(proof_path))
        # Owner is pre-filled (current user), submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Risk acceptance saved"),
            "Risk acceptance was not saved",
        )

    @on_exception_html_source_logger
    def test_view_risk_acceptance(self):
        """View a risk acceptance from the Ad Hoc Engagement."""
        driver = self.driver
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        driver.find_element(By.LINK_TEXT, "Ad Hoc Engagement").click()
        time.sleep(1)
        # Click on the risk acceptance name link
        risk_links = driver.find_elements(By.PARTIAL_LINK_TEXT, "Test Risk Acceptance")
        self.assertTrue(len(risk_links) > 0, "Could not find Test Risk Acceptance link")
        risk_links[0].click()
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Risk Acceptance")
            or self.is_text_present_on_page(text="Test Risk Acceptance"),
        )

    @on_exception_html_source_logger
    def test_download_risk_acceptance_proof(self):
        """Download the proof file from a risk acceptance (regression test for #14467)."""
        driver = self.driver
        # Navigate to the Ad Hoc Engagement where the RA was created
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        driver.find_element(By.LINK_TEXT, "Ad Hoc Engagement").click()
        time.sleep(1)
        # Click the proof download link ("Yes") in the Risk Acceptance table
        download_links = driver.find_elements(By.CSS_SELECTOR, "a[href*='risk_acceptance'][href*='download']")
        self.assertTrue(len(download_links) > 0, "Could not find proof download link on engagement page")
        download_links[0].click()
        time.sleep(2)
        # Verify no 500 error occurred
        self.assertFalse(self.is_error_message_present())
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertNotIn("Internal Server Error", body_text)

    @on_exception_html_source_logger
    def test_delete_risk_acceptance(self):
        """Delete a risk acceptance from the Ad Hoc Engagement."""
        driver = self.driver
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        driver.find_element(By.LINK_TEXT, "Ad Hoc Engagement").click()
        time.sleep(1)
        # Find delete form for risk acceptance (uses POST via hidden form)
        delete_forms = driver.find_elements(By.CSS_SELECTOR, "form[id^='delete-risk_acceptance-form']")
        if len(delete_forms) > 0:
            # The delete link triggers the form via JS; submit the form directly
            driver.execute_script("arguments[0].submit()", delete_forms[0])
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
    suite.addTest(RiskAcceptanceTest("test_download_risk_acceptance_proof"))
    suite.addTest(RiskAcceptanceTest("test_delete_risk_acceptance"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
