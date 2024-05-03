from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import unittest
import sys
from base_test_class import BaseTestCase
from product_test import ProductTest


class EngagementTest(BaseTestCase):

    def test_list_active_engagements_found(self):
        driver = self.driver
        self.goto_active_engagements_overview(driver)
        self.assertIn("edited test engagement</a>", driver.page_source)

    def test_list_active_engagements_empty(self):
        driver = self.driver
        self.goto_active_engagements_overview(driver)
        self.assertNotIn("edited test engagement</a>", driver.page_source)

    def test_list_all_engagements_by_product(self):
        driver = self.driver
        self.goto_all_engagements_by_product_overview(driver)
        self.assertIn("edited test engagement</a>", driver.page_source)

    def test_add_new_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("test engagement")
        driver.find_element(By.ID, "id_name").send_keys("\tthis is engagement test.")
        driver.find_element(By.ID, "id_test_strategy").clear()
        driver.find_element(By.ID, 'id_test_strategy').send_keys("http://localhost:5000")
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        driver.find_element(By.CSS_SELECTOR, "input[value='Done']").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))

    def test_edit_created_new_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "test engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Edit Engagement").click()
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("edited test engagement")
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        driver.find_element(By.CSS_SELECTOR, "input[value='Done']").click()

        self.assertTrue(self.is_success_message_present(text='Engagement updated successfully.'))

    def test_close_new_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "View Engagements").click()
        driver.find_element(By.LINK_TEXT, "edited test engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, "Close Engagement").click()

        self.assertTrue(self.is_success_message_present(text='Engagement closed successfully.'))

    def test_delete_new_closed_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, 'View Engagements').click()

        self.wait_for_datatable_if_content("no_active_engagements", "open_wrapper")

        driver.find_element(By.LINK_TEXT, "edited test engagement").click()
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.LINK_TEXT, 'Delete Engagement').click()
        driver.find_element(By.NAME, 'delete_name').click()

        self.assertTrue(self.is_success_message_present(text='Engagement and relationships removed.'))

    def test_new_ci_cd_engagement(self):
        driver = self.driver
        self.goto_product_overview(driver)
        # wait for product_wrapper div as datatables javascript modifies the DOM on page load.
        driver.find_element(By.ID, 'products_wrapper')
        driver.find_element(By.LINK_TEXT, 'QA Test').click()
        driver.find_element(By.XPATH, "//a[@class='dropdown-toggle active']//span[@class='hidden-xs']").click()
        driver.find_element(By.LINK_TEXT, 'Add New CI/CD Engagement').click()
        driver.find_element(By.ID, "id_name").send_keys("test new ci/cd engagement")
        driver.find_element(By.ID, "id_name").send_keys("\ttest new ci/cd engagement")
        driver.find_element(By.ID, 'id_deduplication_on_engagement').get_attribute('checked')
        driver.find_element(By.CSS_SELECTOR, "input[value='Done']").click()

        self.assertTrue(self.is_success_message_present(text='Engagement added successfully.'))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(BaseTestCase('disable_block_execution'))
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(EngagementTest('test_add_new_engagement'))
    suite.addTest(EngagementTest('test_edit_created_new_engagement'))
    suite.addTest(EngagementTest('test_list_active_engagements_found'))
    suite.addTest(EngagementTest('test_close_new_engagement'))
    suite.addTest(EngagementTest('test_list_active_engagements_empty'))
    suite.addTest(EngagementTest('test_list_all_engagements_by_product'))
    suite.addTest(EngagementTest('test_delete_new_closed_engagement'))
    suite.addTest(EngagementTest('test_new_ci_cd_engagement'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
