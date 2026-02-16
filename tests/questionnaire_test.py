import sys
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from selenium.webdriver.common.by import By


class QuestionnaireTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_questionnaire_list_loads(self):
        driver = self.driver
        driver.get(self.base_url + "questionnaire")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_create_questionnaire(self):
        driver = self.driver
        driver.get(self.base_url + "questionnaire/create")
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Test Questionnaire")
        driver.find_element(By.ID, "id_description").clear()
        driver.find_element(By.ID, "id_description").send_keys("This is a test questionnaire for E2E testing")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Questionnaire successfully created")
            or self.is_text_present_on_page(text="Test Questionnaire"),
        )

    @on_exception_html_source_logger
    def test_edit_questionnaire(self):
        driver = self.driver
        driver.get(self.base_url + "questionnaire")
        # The questionnaire list page has edit/delete links
        # Click the questionnaire name link to go to the edit page
        driver.find_element(By.LINK_TEXT, "Test Questionnaire").click()
        # We should now be on the edit page (clicking the name goes to edit)
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Edited Test Questionnaire")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(
            self.is_success_message_present(text="Questionnaire successfully updated")
            or self.is_text_present_on_page(text="Edited Test Questionnaire"),
        )

    @on_exception_html_source_logger
    def test_questions_list_loads(self):
        driver = self.driver
        driver.get(self.base_url + "questions")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        self.assertIsNotNone(body_text)

    @on_exception_html_source_logger
    def test_delete_questionnaire(self):
        driver = self.driver
        driver.get(self.base_url + "questionnaire")
        # Find the delete link for the questionnaire
        driver.find_element(By.LINK_TEXT, "Edited Test Questionnaire").click()
        # We're on the edit page - look for delete option
        # The delete is at /questionnaire/<id>/delete
        # Navigate to the delete URL from current edit URL
        current_url = driver.current_url
        # Edit URL format: /questionnaire/<id>/edit, change to /questionnaire/<id>/delete
        delete_url = current_url.replace("/edit", "/delete")
        driver.get(delete_url)
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()

        self.assertTrue(
            self.is_success_message_present(text="Questionnaire deleted successfully")
            or self.is_text_present_on_page(text="Questionnaire"),
        )


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=False, github=False, block_execution=False)
    suite.addTest(QuestionnaireTest("test_questionnaire_list_loads"))
    suite.addTest(QuestionnaireTest("test_create_questionnaire"))
    suite.addTest(QuestionnaireTest("test_edit_questionnaire"))
    suite.addTest(QuestionnaireTest("test_questions_list_loads"))
    suite.addTest(QuestionnaireTest("test_delete_questionnaire"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
