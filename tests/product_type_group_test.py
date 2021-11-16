import unittest
import sys
from base_test_class import BaseTestCase
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from group_test import GroupTest


class ProductTypeGroupTest(BaseTestCase):

    def test_group_add_product_type_group(self):
        driver = self.navigate_to_group_view()
        # Open the menu to add product type groups and click the 'Add' button
        driver.find_element(By.ID, "dropdownMenuAddProductTypeGroup").click()
        driver.find_element(By.ID, "addProductTypeGroup").click()
        # Select the product type 'Research and Development'
        try:
            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, 'id_product_types')))
        except TimeoutException:
            self.fail('Timed out waiting for product types dropdown to initialize ')
        driver.execute_script("document.getElementsByName('product_types')[0].style.display = 'inline'")
        element = driver.find_element(By.XPATH, "//select[@name='product_types']")
        product_type_option = element.find_elements(By.TAG_NAME, 'option')[0]
        Select(element).select_by_value(product_type_option.get_attribute("value"))
        # Select the role 'Reader'
        Select(driver.find_element(By.ID, "id_role")).select_by_visible_text("Reader")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Assert the message to determine success status
        self.assertTrue(self.is_success_message_present(text='Product type groups added successfully.'))
        # Query the site to determine if the member has been added
        self.assertEqual(driver.find_elements(By.NAME, "member_product_type")[0].text, "Research and Development")
        self.assertEqual(driver.find_elements(By.NAME, "member_product_type_role")[0].text, "Reader")

    def test_group_edit_product_type_group(self):
        driver = self.navigate_to_group_view()
        # Open the menu to manage members and click the 'Edit' button
        driver.find_elements(By.NAME, "dropdownManageProductTypeGroup")[0].click()
        driver.find_elements(By.NAME, "editProductTypeGroup")[0].click()
        # Select the role 'Owner'
        Select(driver.find_element(By.ID, "id_role")).select_by_visible_text("Owner")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Assert the message to determine success status
        self.assertTrue(self.is_success_message_present(text='Product type group updated successfully.'))
        # Query the site to determine if the member has been edited
        self.assertEqual(driver.find_elements(By.NAME, "member_product_type")[0].text, "Research and Development")
        self.assertEqual(driver.find_elements(By.NAME, "member_product_type_role")[0].text, "Owner")

    def test_group_delete_product_type_group(self):
        driver = self.navigate_to_group_view()
        # Open the menu to manage members and click the 'Delete' button
        driver.find_elements(By.NAME, "dropdownManageProductTypeGroup")[0].click()
        driver.find_elements(By.NAME, "deleteProductTypeGroup")[0].click()
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-danger").click()
        # Assert the message to determine success status
        self.assertTrue(self.is_success_message_present(text='Product type group deleted successfully.'))
        # Query the site to determine if the member has been deleted
        self.assertFalse(driver.find_elements(By.NAME, "member_product_type"))

    def test_product_type_add_product_type_group(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product type page
        driver.get(self.base_url + "product/type")
        driver.find_element(By.ID, "dropdownMenuProductType").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "View").click()
        # Open the menu to add groups and click the 'Add' button
        driver.find_element(By.ID, "dropdownMenuAddProductTypeGroup").click()
        driver.find_element(By.ID, "addProductTypeGroup").click()
        # Select the group 'Group Name'
        try:
            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, 'id_groups')))
        except TimeoutException:
            self.fail('Timed out waiting for groups dropdown to initialize ')
        driver.execute_script("document.getElementsByName('groups')[0].style.display = 'inline'")
        element = driver.find_element(By.XPATH, "//select[@name='groups']")
        group_option = element.find_elements(By.TAG_NAME, 'option')[0]
        Select(element).select_by_value(group_option.get_attribute("value"))
        # Select the role 'Reader'
        Select(driver.find_element(By.ID, "id_role")).select_by_visible_text("Reader")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Assert the message to determine success status
        self.assertTrue(self.is_success_message_present(text='Product type groups added successfully.'))
        # Query the site to determine if the member has been added
        self.assertEqual(driver.find_elements(By.NAME, "product_type_group_group")[0].text, "Group Name")
        self.assertEqual(driver.find_elements(By.NAME, "product_type_group_role")[0].text, "Reader")

    def test_product_type_edit_product_type_group(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product type page
        driver.get(self.base_url + "product/type")
        driver.find_element(By.ID, "dropdownMenuProductType").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "View").click()
        # Open the menu to manage groups and click the 'Edit' button
        # The first group is the group we are looking for
        driver.find_elements(By.NAME, "dropdownManageProductTypeGroup")[0].click()
        driver.find_elements(By.NAME, "editProductTypeGroup")[0].click()
        # Select the role 'Maintainer'
        Select(driver.find_element(By.ID, "id_role")).select_by_visible_text("Maintainer")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Assert the message to determine success status
        self.assertTrue(self.is_success_message_present(text='Product type group updated successfully.'))
        # Query the site to determine if the member has been edited
        self.assertEqual(driver.find_elements(By.NAME, "product_type_group_group")[0].text, "Group Name")
        self.assertEqual(driver.find_elements(By.NAME, "product_type_group_role")[0].text, "Maintainer")

    def test_product_type_delete_product_type_group(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product type page
        driver.get(self.base_url + "product/type")
        driver.find_element(By.ID, "dropdownMenuProductType").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "View").click()
        # Open the menu to manage members and click the 'Delete' button
        # The second group is the group we are looking for
        driver.find_elements(By.NAME, "dropdownManageProductTypeGroup")[0].click()
        driver.find_elements(By.NAME, "deleteProductTypeGroup")[0].click()
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-danger").click()
        # Assert the message to determine success status
        self.assertTrue(self.is_success_message_present(text='Product type group deleted successfully.'))
        # Query the site to determine if the member has been deleted
        self.assertFalse(driver.find_elements(By.NAME, "product_type_group_group"))

    def navigate_to_group_view(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to group management page
        driver.get(self.base_url + "group")
        # Select the previously created group to edit
        # The name is not clickable
        # so we would have to select specific group by filtering list of groups
        driver.find_element(By.ID, "show-filters").click()
        # Insert name to filter by into name box
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Group Name")
        # click on 'apply filter' button
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-sm.btn-secondary").click()
        # only the needed group is now available, proceed with opening the context menu and clicking 'Edit' button
        driver.find_element(By.ID, "dropdownMenuGroup").click()
        driver.find_element(By.ID, "viewGroup").click()

        return driver


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(GroupTest('test_create_group'))
    suite.addTest(ProductTypeGroupTest('test_group_add_product_type_group'))
    suite.addTest(ProductTypeGroupTest('test_group_edit_product_type_group'))
    suite.addTest(ProductTypeGroupTest('test_group_delete_product_type_group'))
    suite.addTest(ProductTypeGroupTest('test_product_type_add_product_type_group'))
    suite.addTest(ProductTypeGroupTest('test_product_type_edit_product_type_group'))
    suite.addTest(ProductTypeGroupTest('test_product_type_delete_product_type_group'))
    suite.addTest(GroupTest('test_group_edit_name_and_global_role'))
    suite.addTest(GroupTest('test_group_delete'))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
