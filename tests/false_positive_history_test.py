import unittest
import sys
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from base_test_class import BaseTestCase
from product_test import ProductTest, WaitForPageLoad


class FalsePositiveHistoryTest(BaseTestCase):

    def create_finding(self, product_name, engagement_name, test_name, finding_name):
        driver = self.driver
        # Navigate to the Product page to select the product we created earlier
        self.goto_product_overview(driver)
        # wait for product_wrapper div as datatables javascript modifies the DOM on page load.
        driver.find_element(By.ID, 'products_wrapper')
        # Select and click on the particular product to create finding for
        driver.find_element(By.LINK_TEXT, product_name).click()
        # Click on the 'Engagement' Dropdown button
        driver.find_element(By.PARTIAL_LINK_TEXT, "Engagement").click()
        # Click on the Add New Engagement option
        driver.find_element(By.LINK_TEXT, "Add New Interactive Engagement").click()
        # Fill up engagement name
        driver.find_element(By.ID, "id_name").send_keys(engagement_name)
        # Click the 'Add Test' button to Add Test to engagement
        driver.find_element(By.NAME, "_Add Tests").click()
        # Fill up test title
        driver.find_element(By.ID, "id_title").send_keys(test_name)
        # Select Test type
        Select(driver.find_element(By.ID, "id_test_type")).select_by_visible_text("Manual Code Review")
        # Select environment
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Test")
        # Click the 'Add Findings' button to Add Finding to Test
        driver.find_element(By.NAME, "_Add Findings").click()
        # Fill up finding title
        driver.find_element(By.ID, "id_title").send_keys(finding_name)
        # cvssv3 field
        driver.find_element(By.ID, "id_cvssv3").send_keys("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        # finding Description
        driver.find_element(By.ID, "id_cvssv3").send_keys(Keys.TAB, "This is just a Test Case Finding")
        # finding Vulnerability Ids
        driver.find_element(By.ID, "id_vulnerability_ids").send_keys("REF-1\nREF-2")
        # Click the Done button
        with WaitForPageLoad(driver, timeout=30):
            driver.find_element(By.XPATH, "//input[@name='_Finished']").click()
        # Query the site to determine if the finding has been added
        self.assertTrue(self.is_text_present_on_page(text=finding_name))
        # Select and click on the finding
        driver.find_element(By.LINK_TEXT, finding_name).click()
        # Return finding URL
        return driver.current_url

    def assert_is_active(self, finding_url):
        driver = self.driver
        driver.get(finding_url)
        self.assertTrue(self.is_element_by_css_selector_present(selector='#notes', text='Active'))
        self.assertFalse(self.is_element_by_css_selector_present(selector='#notes', text='False Positive'))

    def assert_is_false_positive(self, finding_url):
        driver = self.driver
        driver.get(finding_url)
        self.assertFalse(self.is_element_by_css_selector_present(selector='#notes', text='Active'))
        self.assertTrue(self.is_element_by_css_selector_present(selector='#notes', text='False Positive'))

    def edit_toggle_false_positive(self, finding_url):
        driver = self.driver
        # Go to finding page
        driver.get(finding_url)
        # Click on dropdown
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on 'Edit Finding'
        driver.find_element(By.LINK_TEXT, "Edit Finding").click()
        # Click on Active checkbox
        driver.find_element(By.ID, "id_active").click()
        # Click on False Positive checkbox
        driver.find_element(By.ID, "id_false_p").click()
        # Send
        driver.find_element(By.XPATH, "//input[@name='_Finished']").click()

    def bulk_edit(self, finding_url, status_id):
        driver = self.driver
        # Go to finding page
        driver.get(finding_url)
        # Go to test page
        driver.find_element(By.CSS_SELECTOR, "a[title='Test']").click()
        # Bulk edit dropdown menu
        driver.find_element(By.ID, "select_all").click()
        driver.find_element(By.ID, "dropdownMenu2").click()
        # Select Status
        driver.find_element(By.ID, "id_bulk_status").click()
        driver.find_element(By.ID, status_id).click()
        # Submit
        driver.find_element(By.CSS_SELECTOR, "input[type='submit']").click()

    def test_retroactive_edit_finding(self):
        driver = self.driver
        # Create two equal findings on different engagements
        finding_1 = self.create_finding(
            product_name='QA Test',
            engagement_name='FP History Eng 1',
            test_name='FP History Test',
            finding_name='Fake Vulnerability for Edit Test'
        )
        finding_2 = self.create_finding(
            product_name='QA Test',
            engagement_name='FP History Eng 2',
            test_name='FP History Test',
            finding_name='Fake Vulnerability for Edit Test'
        )
        # Assert that both findings are active
        self.assert_is_active(finding_1)
        self.assert_is_active(finding_2)
        # Edit first finding to be a false positive
        self.edit_toggle_false_positive(finding_1)
        # Assert that both findings are false positives
        self.assert_is_false_positive(finding_1)
        self.assert_is_false_positive(finding_2)
        # Reactivate second finding
        self.edit_toggle_false_positive(finding_2)
        # Assert that both findings are active again
        self.assert_is_active(finding_1)
        self.assert_is_active(finding_2)

    def test_retroactive_bulk_edit_finding(self):
        driver = self.driver
        # Create two equal findings on different engagements
        finding_1 = self.create_finding(
            product_name='QA Test',
            engagement_name='FP History Eng 1',
            test_name='FP History Test',
            finding_name='Fake Vulnerability for Bulk Edit Test'
        )
        finding_2 = self.create_finding(
            product_name='QA Test',
            engagement_name='FP History Eng 2',
            test_name='FP History Test',
            finding_name='Fake Vulnerability for Bulk Edit Test'
        )
        # Assert that both findings are active
        self.assert_is_active(finding_1)
        self.assert_is_active(finding_2)
        # Bulk edit first finding to be a false positive
        self.bulk_edit(finding_1, status_id='id_bulk_false_p')
        # Assert that both findings are false positives
        self.assert_is_false_positive(finding_1)
        self.assert_is_false_positive(finding_2)
        # Reactivate second finding
        self.bulk_edit(finding_2, status_id='id_bulk_active')
        # Assert that both findings are active again
        self.assert_is_active(finding_1)
        self.assert_is_active(finding_2)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(BaseTestCase('enable_block_execution'))
    suite.addTest(BaseTestCase('disable_deduplication'))
    suite.addTest(BaseTestCase('enable_false_positive_history'))
    suite.addTest(BaseTestCase('enable_retroactive_false_positive_history'))
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(FalsePositiveHistoryTest('test_retroactive_edit_finding'))
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(FalsePositiveHistoryTest('test_retroactive_bulk_edit_finding'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
