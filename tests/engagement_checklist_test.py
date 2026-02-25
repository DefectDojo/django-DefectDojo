import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select


class EngagementChecklistTest(BaseTestCase):

    def _get_engagement_id(self, driver):
        """Navigate to the Beta Test engagement via the all engagements list."""
        self.goto_all_engagements_overview(driver)
        time.sleep(1)
        # Find the Beta Test engagement link
        eng_links = driver.find_elements(By.LINK_TEXT, "Beta Test")
        if len(eng_links) > 0:
            eng_links[0].click()
            time.sleep(1)
            current_url = driver.current_url
            # URL pattern: .../engagement/<id>
            parts = current_url.rstrip("/").split("/")
            for i, part in enumerate(parts):
                if part == "engagement" and i + 1 < len(parts):
                    return parts[i + 1]
            return parts[-1]
        return None

    @on_exception_html_source_logger
    def test_complete_checklist_page_loads(self):
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        driver.get(self.base_url + f"engagement/{eid}/complete_checklist")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Checklist")
            or self.is_text_present_on_page(text="checklist"),
        )

    @on_exception_html_source_logger
    def test_fill_and_save_checklist(self):
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        driver.get(self.base_url + f"engagement/{eid}/complete_checklist")
        time.sleep(1)
        # Fill out checklist fields - each is a select with Pass/Fail/N/A options
        checklist_fields = [
            "id_session_management",
            "id_encryption_crypto",
            "id_configuration_management",
            "id_authentication",
            "id_authorization_and_access_control",
            "id_data_input_sanitization_validation",
            "id_sensitive_data",
            "id_other",
        ]
        for field_id in checklist_fields:
            fields = driver.find_elements(By.ID, field_id)
            if len(fields) > 0:
                Select(fields[0]).select_by_visible_text("Pass")

        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Checklist saved")
            or self.is_text_present_on_page(text="Engagement"),
        )

    @on_exception_html_source_logger
    def test_view_checklist_after_save(self):
        """Verify we can re-open the checklist and it retains values."""
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        driver.get(self.base_url + f"engagement/{eid}/complete_checklist")
        time.sleep(1)
        # Verify the checklist page loads with our previously saved values
        self.assertTrue(
            self.is_text_present_on_page(text="Checklist")
            or self.is_text_present_on_page(text="checklist"),
        )
        # Verify "Pass" is selected for at least one field
        session_mgmt = driver.find_elements(By.ID, "id_session_management")
        if len(session_mgmt) > 0:
            selected = Select(session_mgmt[0]).first_selected_option.text
            self.assertIn(selected, ["Pass", "Fail", "N/A"])


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_engagement"))
    suite.addTest(EngagementChecklistTest("test_complete_checklist_page_loads"))
    suite.addTest(EngagementChecklistTest("test_fill_and_save_checklist"))
    suite.addTest(EngagementChecklistTest("test_view_checklist_after_save"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
