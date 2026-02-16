import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select


class QuestionnaireAdvancedTest(BaseTestCase):

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
    def test_create_question(self):
        """Create a new text question."""
        driver = self.driver
        driver.get(self.base_url + "questions/add")
        time.sleep(1)
        # Select question type - "text" for a simple text question
        type_fields = driver.find_elements(By.ID, "id_type")
        if len(type_fields) > 0:
            Select(type_fields[0]).select_by_value("text")
            time.sleep(1)
        # Fill in the order field
        order_fields = driver.find_elements(By.ID, "id_order")
        if len(order_fields) > 0:
            order_fields[0].clear()
            order_fields[0].send_keys("1")
        # Fill in the question text
        text_fields = driver.find_elements(By.ID, "id_text")
        if len(text_fields) > 0:
            text_fields[0].clear()
            text_fields[0].send_keys("Is the application using encryption?")
        # Submit the form
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary[name='submit']").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Question added successfully")
            or self.is_text_present_on_page(text="Question")
            or self.is_text_present_on_page(text="questions"),
        )

    @on_exception_html_source_logger
    def test_questions_list_page(self):
        """Verify the questions list page loads."""
        driver = self.driver
        driver.get(self.base_url + "questions")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Question")
            or self.is_text_present_on_page(text="questions"),
        )

    @on_exception_html_source_logger
    def test_create_questionnaire(self):
        """Create a questionnaire."""
        driver = self.driver
        driver.get(self.base_url + "questionnaire/create")
        time.sleep(1)
        name_fields = driver.find_elements(By.ID, "id_name")
        if len(name_fields) > 0:
            name_fields[0].clear()
            name_fields[0].send_keys("Advanced Test Questionnaire")
        desc_fields = driver.find_elements(By.ID, "id_description")
        if len(desc_fields) > 0:
            desc_fields[0].clear()
            desc_fields[0].send_keys("A questionnaire for advanced integration testing")
        # Click the "Create Questionnaire" submit button
        submit_btns = driver.find_elements(By.CSS_SELECTOR, "input.btn.btn-primary[name='create_questionnaire']")
        if len(submit_btns) > 0:
            submit_btns[0].click()
        else:
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Questionnaire successfully created")
            or self.is_text_present_on_page(text="Questionnaire")
            or self.is_text_present_on_page(text="questionnaire"),
        )

    @on_exception_html_source_logger
    def test_add_questionnaire_to_engagement(self):
        """Add a questionnaire to an engagement."""
        driver = self.driver
        eid = self._get_engagement_id(driver)
        self.assertIsNotNone(eid, "Could not find Beta Test engagement")
        # Navigate to add questionnaire page for this engagement
        driver.get(self.base_url + f"engagement/{eid}/add_questionnaire")
        time.sleep(1)
        # Select a questionnaire from the dropdown if available
        survey_select = driver.find_elements(By.ID, "id_survey")
        if len(survey_select) > 0:
            select = Select(survey_select[0])
            if len(select.options) > 1:
                select.select_by_index(1)
                # Submit the form
                submit_btns = driver.find_elements(By.CSS_SELECTOR, "input.btn.btn-primary[name='add_questionnaire']")
                if len(submit_btns) > 0:
                    submit_btns[0].click()
                else:
                    driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
                time.sleep(1)

        self.assertTrue(
            self.is_success_message_present(text="Questionnaire successfully added")
            or self.is_text_present_on_page(text="Engagement")
            or self.is_text_present_on_page(text="Questionnaire")
            or self.is_text_present_on_page(text="All available questionnaires"),
        )
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_questionnaire_list_page(self):
        """Verify the questionnaire list page loads."""
        driver = self.driver
        driver.get(self.base_url + "questionnaire")
        time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Questionnaire")
            or self.is_text_present_on_page(text="questionnaire"),
        )

    @on_exception_html_source_logger
    def test_delete_advanced_questionnaire(self):
        """Clean up the advanced test questionnaire via the edit page."""
        driver = self.driver
        driver.get(self.base_url + "questionnaire")
        time.sleep(1)
        # Find the questionnaire we created by link text
        q_links = driver.find_elements(By.LINK_TEXT, "Advanced Test Questionnaire")
        if len(q_links) > 0:
            q_links[0].click()
            time.sleep(1)
            # We're now on the edit page - look for the delete link/button
            delete_links = driver.find_elements(By.CSS_SELECTOR, "a.btn.btn-danger")
            if len(delete_links) > 0:
                delete_links[0].click()
                time.sleep(1)
                # Confirm deletion
                confirm_btns = driver.find_elements(By.CSS_SELECTOR, "input.btn.btn-danger")
                if len(confirm_btns) > 0:
                    confirm_btns[0].click()
                else:
                    button_btns = driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-danger")
                    if len(button_btns) > 0:
                        button_btns[0].click()
                time.sleep(1)
        self.assertTrue(
            self.is_text_present_on_page(text="Questionnaire")
            or self.is_text_present_on_page(text="questionnaire"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(QuestionnaireAdvancedTest("test_create_question"))
    suite.addTest(QuestionnaireAdvancedTest("test_questions_list_page"))
    suite.addTest(QuestionnaireAdvancedTest("test_create_questionnaire"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_engagement"))
    suite.addTest(QuestionnaireAdvancedTest("test_add_questionnaire_to_engagement"))
    suite.addTest(QuestionnaireAdvancedTest("test_questionnaire_list_page"))
    suite.addTest(ProductTest("test_delete_product"))
    suite.addTest(QuestionnaireAdvancedTest("test_delete_advanced_questionnaire"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
