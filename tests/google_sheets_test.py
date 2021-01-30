import unittest
import sys
import os
import io
import tempfile
from base_test_class import BaseTestCase


class GoogleSheetsConfigurationTest(BaseTestCase):
    def test_configure_google_sheets(self):
        driver = self.login_page()
        self.goto_google_sheets_configuration_form(driver)
        # gdrive link (also as github secret)
        driver.find_element_by_id("id_drive_folder_ID").send_keys(os.getenv('GOOGLE_SHEETS_MADCHAP_GDRIVE_FOLDER'))
        # email address from github secret
        driver.find_element_by_id("id_email_address").send_keys(os.getenv('GOOGLE_SHEETS_MADCHAP_EMAIL'))
        # upload json file
        json_file = io.BytesIO(os.getenv('GOOGLE_SHEETS_MADCHAP_PRIVATE_JSON'))
        tmpfile = tempfile.NamedTemporaryFile()
        tmpfile.write(json_file.read())
        driver.find_element_by_name("cred_file").send_keys(tmpfile.name)
        tmpfile.close()
        # submit
        driver.find_element_by_name("update").click()
        # Assert ot the query to determine status of failure
        self.assertTrue(self.is_success_message_present(text='Files updated successfully'))


def add_file_tests_to_suite(suite):
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(GoogleSheetsConfigurationTest('test_configure_google_sheets'))

    return suite


def suite():
    suite = unittest.TestSuite()
    add_file_tests_to_suite(suite)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
