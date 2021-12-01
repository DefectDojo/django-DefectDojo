import time
import unittest
import sys
from pathlib import Path
from base_test_class import BaseTestCase
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import ActionChains


class UserTest(BaseTestCase):

    @staticmethod
    def add_user_read_only_parameter():
        f = open('dojo/settings/local_settings.py', 'w')
        f.write("USER_PROFILE_EDITABLE=False")
        f.close()

    @staticmethod
    def unset_user_read_only_parameter():
        f = open('dojo/settings/local_settings.py', 'w')
        f.write("USER_PROFILE_EDITABLE=True")
        f.close()

    @staticmethod
    def reload_service():
        Path("dojo/settings/settings.py").touch()

    def test_create_user(self):
        # Login to the site.
        driver = self.driver
        # Navigate to the User managegement page
        driver.get(self.base_url + "user")
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the add prodcut button
        driver.find_element(By.LINK_TEXT, "New User").click()
        # Fill in the Necessary User Details
        # username, first name, last name, email, and permissions
        # Don't forget to clear before inserting
        # username
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys("propersahm")
        # password
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys("Def3ctD0jo&")
        # First Name
        driver.find_element(By.ID, "id_first_name").clear()
        driver.find_element(By.ID, "id_first_name").send_keys("Proper")
        # Last Name
        driver.find_element(By.ID, "id_last_name").clear()
        driver.find_element(By.ID, "id_last_name").send_keys("Samuel")
        # Email Address
        driver.find_element(By.ID, "id_email").clear()
        driver.find_element(By.ID, "id_email").send_keys("propersam@example.com")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the user has been created

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='User added successfully.') or
            self.is_help_message_present(text='A user with that username already exists.'))

    def login_standard_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys('propersahm')
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys('Def3ctD0jo&')
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()

        self.assertFalse(self.is_element_by_css_selector_present('.alert-danger', 'Please enter a correct username and password'))
        return driver

    def test_user_edit_permissions(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select the previously created user to edit
        # The User name is not clickable
        # so we would have to select specific user by filtering list of users
        driver.find_element(By.ID, "show-filters").click()  # open d filters
        # Insert username to filter by into user name box
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys("propersahm")
        # click on 'apply filter' button
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-sm.btn-secondary").click()
        # only the needed user is now available, proceed with opening the context menu and clicking 'Edit' button
        driver.find_element(By.ID, "dropdownMenuUser").click()
        driver.find_element(By.ID, "editUser").click()
        # Select Superuser and Staff Permission
        driver.find_element(By.NAME, "is_superuser").click()
        driver.find_element(By.NAME, "is_staff").click()
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the User permission has been changed

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='User saved successfully.'))

    def test_user_delete(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "user")
        # Select A user to edit
        # The User name is not clickable
        # so we would have to select specific user by filtering list of users
        driver.find_element(By.ID, "show-filters").click()  # open d filters
        # Insert username to filter by into user name box
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys("propersahm")
        # click on 'apply filter' button
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-sm.btn-secondary").click()
        # only the needed user is now available, proceed with clicking 'View' button
        driver.find_element(By.ID, "dropdownMenuUser").click()
        driver.find_element(By.ID, "viewUser").click()
        # in View User dialog open the menu to click the delete entry
        driver.find_element(By.ID, "dropdownMenu1").click()
        driver.find_element(By.ID, "deleteUser").click()
        # confirm deletion, by clicking delete a second time
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()
        # Query the site to determine if the User has been deleted

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='User and relationships removed.'))

    def test_user_notifications_change(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        wait = WebDriverWait(driver, 5)
        actions = ActionChains(driver)
        configuration_menu = driver.find_element(By.ID, 'menu_configuration')
        actions.move_to_element(configuration_menu).perform()
        wait.until(EC.visibility_of_element_located((By.LINK_TEXT, "Notifications"))).click()

        originally_selected = {
            'product_added': driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']").is_selected(),
            'scan_added': driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").is_selected()
        }

        driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']").click()
        driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").click()

        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text='Settings saved'))
        self.assertNotEqual(originally_selected['product_added'],
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']").is_selected())
        self.assertNotEqual(originally_selected['scan_added'],
            driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").is_selected())

    def test_standard_user_login(self):
        self.login_standard_page()

    def test_admin_profile_form(self):
        self.add_user_read_only_parameter()
        self.reload_service()
        self.driver.get(self.base_url + "profile")
        self.assertTrue(self.driver.find_element(By.ID, 'id_first_name').is_enabled())

    def test_user_profile_form_disabled(self):
        self.driver.get(self.base_url + "profile")
        self.assertFalse(self.driver.find_element(By.ID, 'id_first_name').is_enabled())

    def test_user_profile_form_enabled(self):
        self.unset_user_read_only_parameter()
        # Do not do function reload to avoid double reloading
        time.sleep(5)
        self.driver.get(self.base_url + "profile")
        self.assertTrue(self.driver.find_element(By.ID, 'id_first_name').is_enabled())

    def test_forgot_password(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        # Click on link on login screen
        driver.find_element_by_id("reset-password").click()
        # Submit "Forgot password" form
        driver.find_element_by_id("id_email").send_keys("propersam@example.com")
        driver.find_element_by_id("reset-password").click()

        self.assertTrue(self.is_text_present_on_page(text='We’ve emailed you instructions for setting your password'))


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(UserTest('test_create_user'))
    suite.addTest(UserTest('test_admin_profile_form'))
    suite.addTest(BaseTestCase('test_logout'))
    suite.addTest(UserTest('test_standard_user_login'))
    suite.addTest(UserTest('test_user_profile_form_disabled'))
    suite.addTest(UserTest('test_user_profile_form_enabled'))
    suite.addTest(BaseTestCase('test_logout'))
    suite.addTest(UserTest('test_forgot_password'))
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(UserTest('test_user_edit_permissions'))
    suite.addTest(UserTest('test_user_delete'))

    # not really for the user we created, but still related to user settings
    suite.addTest(UserTest('test_user_notifications_change'))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
