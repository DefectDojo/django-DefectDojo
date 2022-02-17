from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.keys import Keys
import unittest
import sys
from base_test_class import BaseTestCase, on_exception_html_source_logger
from product_test import ProductTest, WaitForPageLoad
from selenium.webdriver.common.by import By


class TestUnitTest(BaseTestCase):

    def test_view_test(self):
        # View existing test from ProductTest()
        # Login to the site.
        driver = self.driver

        # goto engagemnent list (and wait for javascript to load)
        self.goto_all_engagements_overview(driver)

        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Ad Hoc Engagement").click()

        driver.find_element(By.PARTIAL_LINK_TEXT, "Pen Test").click()

        driver.find_element(By.ID, "select_all").click()

        # bulk edit dropdown menu
        driver.find_element(By.ID, "dropdownMenu2").click()

        bulk_edit_menu = driver.find_element(By.ID, "bulk_edit_menu")
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_active").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_verified").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_false_p").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_out_of_scope").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_is_mitigated").is_enabled(), False)

        driver.find_element(By.ID, "id_bulk_status").click()

        bulk_edit_menu = driver.find_element(By.ID, "bulk_edit_menu")
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_active").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_verified").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_false_p").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_out_of_scope").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_is_mitigated").is_enabled(), True)

    def test_create_test(self):
        # To create test for a product
        # You must have an engagement and then tests are packed in engagements
        # Login to the site.
        # Username and password will be gotten from environ
        driver = self.driver
        # Navigate to the Product page to select the product we created earlier
        self.goto_product_overview(driver)
        # wait for product_wrapper div as datatables javascript modifies the DOM on page load.
        driver.find_element(By.ID, 'products_wrapper')
        # Select and click on the particular product to create test for
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on the 'Engagement' Dropdown button
        driver.find_element(By.PARTIAL_LINK_TEXT, "Engagement").click()
        # 'click' the Add New Engagement option
        driver.find_element(By.LINK_TEXT, "Add New Interactive Engagement").click()
        # Keep a good practice of clearing field before entering value
        # fill up at least all required input field options.
        # fields: 'Name', 'Description', 'Target Start', 'Target End', 'Testing Lead' and 'Status'
        # engagement name
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Beta Test")
        # engagement description
        # Tab into the description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element(By.ID, "id_name").send_keys("\tRunning Test on product before approving and push to production.")
        # engagement target start and target end already have defaults
        # we can safely skip
        # Testing Lead: This can be the logged in user
        Select(driver.find_element(By.ID, "id_lead")).select_by_visible_text('Admin User (admin)')
        # engagement status
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        # "Click" the 'Add Test' button to Add Test to engagement
        driver.find_element(By.NAME, "_Add Tests").click()
        # Fill at least required fields needed to create Test
        # Test title
        driver.find_element(By.ID, "id_title").clear()  # clear field before inserting anything
        driver.find_element(By.ID, "id_title").send_keys("Quick Security Testing")
        # Select Test type
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Manual Code Review")
        # skip Target start and Target end leaving their default values
        # Select Testing Environment
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the Test has been added

        # Assert on the query to determine success or failure
        self.assertTrue(self.is_success_message_present(text='Test added successfully'))

    def test_edit_test(self):
        # Login to the site.
        driver = self.driver
        # Navigate to the engagement page
        self.goto_active_engagements_overview(driver)
        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the Edit Test option
        driver.find_element(By.LINK_TEXT, "Edit Test").click()
        # Change Testing Environment to Staging from Development
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Staging")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the Test has been updated

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Test saved.'))

    def test_add_note(self):
        # Login to the site.
        driver = self.driver
        # Navigate to the engagement page
        self.goto_active_engagements_overview(driver)
        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Notes are on the view_test page
        driver.find_element(By.ID, "id_entry").clear()
        driver.find_element(By.ID, "id_entry").send_keys("This is a sample note for all to see.")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.XPATH, "//input[@value='Add Note']").click()
        # Query the site to determine if the Test has been updated

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Note added successfully.'))

    def test_add_test_finding(self):
        # Test To Add Finding To Test
        # Login to the site.
        driver = self.driver
        # Navigate to the engagement page
        self.goto_active_engagements_overview(driver)
        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        # "Click" the dropdown button to see options
        test_menu = driver.find_element(By.ID, "test-menu")
        test_menu.click()

        driver.find_element(By.LINK_TEXT, "Add Finding to Test").click()
        # Keep a good practice of clearing field before entering value
        # fill up at least all required input field options.
        # fields: 'Title', 'Date', 'Severity', 'Description', 'Mitigation' and 'Impact'
        # finding Title
        driver.find_element(By.ID, "id_title").clear()
        driver.find_element(By.ID, "id_title").send_keys("App Vulnerable to XSS2")
        # finding Date as a default value and can be safely skipped
        # finding Severity
        Select(driver.find_element(By.ID, "id_severity")).select_by_visible_text("High")
        # cvss
        driver.find_element(By.ID, "id_cvssv3").send_keys("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        # finding Description
        driver.find_element(By.ID, "id_cvssv3").send_keys(Keys.TAB, "This is just a Test Case Finding2")
        # Finding Mitigation
        # Use Javascript to bypass the editor by making Setting textArea style from none to inline
        # Any Text written to textarea automatically reflects in Editor field.
        driver.execute_script("document.getElementsByName('mitigation')[0].style.display = 'inline'")
        driver.find_element(By.NAME, "mitigation").send_keys(Keys.TAB, "How to mitigate this finding2")
        # Finding Impact
        # Use Javascript to bypass the editor by making Setting textArea style from none to inline
        # Any Text written to textarea automatically reflects in Editor field.
        driver.execute_script("document.getElementsByName('impact')[0].style.display = 'inline'")
        driver.find_element(By.NAME, "impact").send_keys(Keys.TAB, "This has a very critical effect on production2")
        # Add an endpoint
        driver.find_element(By.ID, "id_endpoints_to_add").send_keys("product2.finding.com")
        # "Click" the Done button to Add the finding with other defaults
        with WaitForPageLoad(driver, timeout=30):
            driver.find_element(By.XPATH, "//input[@name='_Finished']").click()
        # Query the site to determine if the finding has been added

        # Assert to the query to dtermine status of failure
        self.assertTrue(self.is_text_present_on_page(text='App Vulnerable to XSS2'))
        # Select and click on the finding to check if endpoint has been added
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS2").click()
        self.assertTrue(self.is_text_present_on_page(text='product2.finding.com'))

    def test_add_stub_finding(self):
        # Login to the site.
        driver = self.driver

        # Select the previously created test
        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()

        # Enter the title of the stub finding
        # Keep a good practice of clearing field before entering value
        driver.find_element(By.ID, "quick_add_finding").clear()
        driver.find_element(By.ID, "quick_add_finding").send_keys("App Vulnerable to XSS3")
        # Click on Add Potential Finding
        driver.find_element(By.ID, "the_button").click()

    def test_add_and_promote_stub_finding(self):

        self.test_add_stub_finding()

        driver = self.driver

        # Select the previously created test
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()

        # Click on link of finding name to promote to finding
        driver.find_elements(By.NAME, "stub_finding_name")[0].click()
        # Check we have the correct stub finding
        self.assertEqual(driver.find_element(By.ID, "id_title").get_attribute('value'), 'App Vulnerable to XSS3')
        # Edit finding Description
        driver.find_element(By.ID, "id_cvssv3_score").send_keys(Keys.TAB, Keys.TAB, "This is a promoted stub finding")
        # "Click" the Done button to Edit the finding
        driver.find_element(By.ID, "submit").click()

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Finding promoted successfully'))

    @on_exception_html_source_logger
    def test_add_and_delete_stub_finding(self):

        self.test_add_stub_finding()

        driver = self.driver

        # Select the previously created test
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()

        # Click on Delete butten
        driver.find_elements(By.NAME, "stub_finding_delete")[0].click()
        # Accept popup
        driver.switch_to.alert.accept()
        # Check the stub finding is deleted
        self.assertFalse(driver.find_elements(By.NAME, "stub_finding_name"))

    def test_merge_findings(self):
        # View existing test from ProductTest()
        # Login to the site.
        driver = self.driver

        # Navigate to the engagement page
        self.goto_active_engagements_overview(driver)
        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()

        driver.find_element(By.ID, "select_all").click()

        driver.find_element(By.ID, "merge_findings").click()

        Select(driver.find_element(By.ID, "id_finding_action")).select_by_visible_text('Inactive')

        Select(driver.find_element(By.ID, "id_findings_to_merge")).select_by_visible_text('App Vulnerable to XSS3')

        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def test_delete_test(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the engagement page
        self.goto_active_engagements_overview(driver)
        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Beta Test").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Quick Security Testing").click()
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the Edit Test option
        driver.find_element(By.LINK_TEXT, "Delete Test").click()
        # "Click" the delete button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()
        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Test and relationships removed.'))


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(ProductTest('test_add_product_finding'))
    suite.addTest(TestUnitTest('test_view_test'))
    suite.addTest(TestUnitTest('test_create_test'))
    suite.addTest(TestUnitTest('test_edit_test'))
    suite.addTest(TestUnitTest('test_add_test_finding'))
    suite.addTest(TestUnitTest('test_add_and_promote_stub_finding'))
    suite.addTest(TestUnitTest('test_merge_findings'))
    suite.addTest(TestUnitTest('test_add_and_delete_stub_finding'))
    suite.addTest(TestUnitTest('test_add_note'))
    suite.addTest(TestUnitTest('test_delete_test'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
