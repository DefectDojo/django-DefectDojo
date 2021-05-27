import unittest
import sys
from base_test_class import BaseTestCase
from selenium.webdriver.support.ui import Select
from user_test import UserTest
from product_test import ProductTest


class ProductMemberTest(BaseTestCase):

    def test_user_add_product_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select and click on the particular user to view
        driver.find_element_by_link_text("propersahm").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductMember'):
            # Open the menu to add users and click the 'Add' button
            driver.find_element_by_id("dropdownMenuAddProductMember").click()
            driver.find_element_by_id("addProductMember").click()
            # Select the product type 'Research and Development'
            Select(driver.find_element_by_id("id_product")).select_by_visible_text("QA Test")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product member added successfully.'))
            # Query the site to determine if the member has been added
            self.assertEqual(driver.find_elements_by_name("member_product")[0].text, "QA Test")
            self.assertEqual(driver.find_elements_by_name("member_product_role")[0].text, "Reader")
        else:
            print('--------------------------------')
            print('test_user_add_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_user_edit_product_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select and click on the particular user to view
        driver.find_element_by_link_text("propersahm").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductMember'):
            # Open the menu to manage members and click the 'Edit' button
            driver.find_elements_by_name("dropdownManageProductMember")[0].click()
            driver.find_elements_by_name("editProductMember")[0].click()
            # Select the role 'Owner'
            Select(driver.find_element_by_id("id_role")).select_by_visible_text("Maintainer")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product member updated successfully.'))
            # Query the site to determine if the member has been edited
            self.assertEqual(driver.find_elements_by_name("member_product")[0].text, "QA Test")
            self.assertEqual(driver.find_elements_by_name("member_product_role")[0].text, "Maintainer")
        else:
            print('--------------------------------')
            print('test_edit_add_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_user_delete_product_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select and click on the particular user to view
        driver.find_element_by_link_text("propersahm").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductMember'):
            # Open the menu to manage members and click the 'Delete' button
            driver.find_elements_by_name("dropdownManageProductMember")[0].click()
            driver.find_elements_by_name("deleteProductMember")[0].click()
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-danger").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product member deleted successfully.'))
            # Query the site to determine if the member has been deleted
            self.assertFalse(driver.find_elements_by_name("member_product"))
        else:
            print('--------------------------------')
            print('test_user_delete_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_product_add_product_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        if self.is_element_by_id_present('dropdownMenuAddProductMember'):
            # Open the menu to add users and click the 'Add User' button
            driver.find_element_by_id("dropdownMenuAddProductMember").click()
            driver.find_element_by_id("addProductMember").click()
            # Select the user 'propersahm'
            Select(driver.find_element_by_id("id_user")).select_by_visible_text("Proper Samuel (propersahm)")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product member added successfully.'))
            # Query the site to determine if the member has been added
            self.assertEqual(driver.find_elements_by_name("member_user")[0].text, "Proper Samuel (propersahm)")
            self.assertEqual(driver.find_elements_by_name("member_role")[0].text, "Reader")
        else:
            print('--------------------------------')
            print('test_product_add_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_product_edit_product_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductMember'):
            # Open the menu to manage members and click the 'Edit' button
            driver.find_elements_by_name("dropdownManageProductMember")[0].click()
            driver.find_elements_by_name("editProductMember")[0].click()
            # Select the role 'Owner'
            Select(driver.find_element_by_id("id_role")).select_by_visible_text("Maintainer")
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-primary").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product member updated successfully.'))
            # Query the site to determine if the member has been edited
            self.assertEqual(driver.find_elements_by_name("member_user")[0].text, "Proper Samuel (propersahm)")
            self.assertEqual(driver.find_elements_by_name("member_role")[0].text, "Maintainer")
        else:
            print('--------------------------------')
            print('test_product_edit_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')

    def test_product_delete_product_member(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # Only execute test case when authorization v2 is activated
        if self.is_element_by_id_present('dropdownMenuAddProductMember'):
            # Open the menu to manage members and click the 'Delete' button
            driver.find_elements_by_name("dropdownManageProductMember")[0].click()
            driver.find_elements_by_name("deleteProductMember")[0].click()
            # "Click" the submit button to complete the transaction
            driver.find_element_by_css_selector("input.btn.btn-danger").click()
            # Assert the message to determine success status
            self.assertTrue(self.is_success_message_present(text='Product member deleted successfully.'))
            # Query the site to determine if the member has been deleted
            self.assertFalse(driver.find_elements_by_name("member_user"))
        else:
            print('--------------------------------')
            print('test_product_delete_product_member: Not executed because legacy authorization is active')
            print('--------------------------------')


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(UserTest('test_create_user'))
    suite.addTest(ProductMemberTest('test_user_add_product_member'))
    suite.addTest(ProductMemberTest('test_user_edit_product_member'))
    suite.addTest(ProductMemberTest('test_user_delete_product_member'))
    suite.addTest(ProductMemberTest('test_product_add_product_member'))
    suite.addTest(ProductMemberTest('test_product_edit_product_member'))
    suite.addTest(ProductMemberTest('test_product_delete_product_member'))
    suite.addTest(UserTest('test_user_delete'))
    suite.addTest(ProductTest('test_delete_product'))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
