import unittest
import sys
from base_test_class import BaseTestCase
from selenium.webdriver.support.ui import Select
from user_test import UserTest


class ProductTypeMemberTest(BaseTestCase):

    def test_user_add_product_type_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select and click on the particular user to view
        driver.find_element_by_link_text("propersahm").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductTypeMember'):
            # Open the menu to add users and click the 'Add' button
            driver.find_element_by_id("dropdownMenuAddProductTypeMember").click()
            driver.find_element_by_id("addProductTypeMember").click()
            # Select the product type 'Research and Development'
            Select(driver.find_element_by_id("id_product_type")).select_by_visible_text("Research and Development")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product type member added successfully.'))
            # Query the site to determine if the member has been added
            self.assertEqual(driver.find_elements_by_name("member_product_type")[0].text, "Research and Development")
            self.assertEqual(driver.find_elements_by_name("member_product_type_role")[0].text, "Reader")
        else:
            print('--------------------------------')
            print('test_user_add_product_type_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_user_edit_product_type_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select and click on the particular user to view
        driver.find_element_by_link_text("propersahm").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductTypeMember'):
            # Open the menu to manage members and click the 'Edit' button
            driver.find_elements_by_name("dropdownManageProductTypeMember")[0].click()
            driver.find_elements_by_name("editProductTypeMember")[0].click()
            # Select the role 'Owner'
            Select(driver.find_element_by_id("id_role")).select_by_visible_text("Owner")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product type member updated successfully.'))
            # Query the site to determine if the member has been edited
            self.assertEqual(driver.find_elements_by_name("member_product_type")[0].text, "Research and Development")
            self.assertEqual(driver.find_elements_by_name("member_product_type_role")[0].text, "Owner")
        else:
            print('--------------------------------')
            print('test_user_edit_product_type_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_user_delete_product_type_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select and click on the particular user to view
        driver.find_element_by_link_text("propersahm").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductTypeMember'):
            # Open the menu to manage members and click the 'Delete' button
            driver.find_elements_by_name("dropdownManageProductTypeMember")[0].click()
            driver.find_elements_by_name("deleteProductTypeMember")[0].click()
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-danger").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product type member deleted successfully.'))
            # Query the site to determine if the member has been deleted
            self.assertFalse(driver.find_elements_by_name("member_product_type"))
        else:
            print('--------------------------------')
            print('test_user_delete_product_type_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_product_type_add_product_type_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product type page
        driver.get(self.base_url + "product/type")
        driver.find_element_by_id("dropdownMenuProductType").click()
        driver.find_element_by_partial_link_text("View").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductTypeMember'):
            # Open the menu to add users and click the 'Add' button
            driver.find_element_by_id("dropdownMenuAddProductTypeMember").click()
            driver.find_element_by_id("addProductTypeMember").click()
            # Select the user 'propersahm'
            Select(driver.find_element_by_id("id_user")).select_by_visible_text("Proper Samuel (propersahm)")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product type member added successfully.'))
            # Query the site to determine if the member has been added
            self.assertEqual(driver.find_elements_by_name("member_user")[1].text, "Proper Samuel (propersahm)")
            self.assertEqual(driver.find_elements_by_name("member_role")[1].text, "Reader")
        else:
            print('--------------------------------')
            print('test_product_type_add_product_type_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_product_type_edit_product_type_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product type page
        driver.get(self.base_url + "product/type")
        driver.find_element_by_id("dropdownMenuProductType").click()
        driver.find_element_by_partial_link_text("View").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductTypeMember'):
            # Open the menu to manage members and click the 'Edit' button
            # The first member in the list is the admin user which was inserted by a fixture
            # The second member is the user we are looking for
            driver.find_elements_by_name("dropdownManageProductTypeMember")[1].click()
            driver.find_elements_by_name("editProductTypeMember")[1].click()
            # Select the role 'Owner'
            Select(driver.find_element_by_id("id_role")).select_by_visible_text("Maintainer")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product type member updated successfully.'))
            # Query the site to determine if the member has been edited
            self.assertEqual(driver.find_elements_by_name("member_user")[1].text, "Proper Samuel (propersahm)")
            self.assertEqual(driver.find_elements_by_name("member_role")[1].text, "Maintainer")
        else:
            print('--------------------------------')
            print('test_product_type_edit_product_type_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_product_type_delete_product_type_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product type page
        driver.get(self.base_url + "product/type")
        driver.find_element_by_id("dropdownMenuProductType").click()
        driver.find_element_by_partial_link_text("View").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductTypeMember'):
            # Open the menu to manage members and click the 'Delete' button
            # The first member in the list is the admin user which was inserted by a fixture
            # The second member is the user we are looking for
            driver.find_elements_by_name("dropdownManageProductTypeMember")[1].click()
            driver.find_elements_by_name("deleteProductTypeMember")[1].click()
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-danger").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product type member deleted successfully.'))
            # Query the site to determine if the member has been deleted
            self.assertTrue(len(driver.find_elements_by_name("member_user")) == 1)
        else:
            print('--------------------------------')
            print('test_product_delete_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(UserTest('test_create_user'))
    suite.addTest(ProductTypeMemberTest('test_user_add_product_type_member'))
    suite.addTest(ProductTypeMemberTest('test_user_edit_product_type_member'))
    suite.addTest(ProductTypeMemberTest('test_user_delete_product_type_member'))
    suite.addTest(ProductTypeMemberTest('test_product_type_add_product_type_member'))
    suite.addTest(ProductTypeMemberTest('test_product_type_edit_product_type_member'))
    suite.addTest(ProductTypeMemberTest('test_product_type_delete_product_type_member'))
    suite.addTest(UserTest('test_user_delete'))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
