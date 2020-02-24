from selenium import webdriver
from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
import os


class UserTest(unittest.TestCase):
    def setUp(self):
        # Initialize the driver
        # When used with Travis, chromdriver is stored in the same
        # directory as the unit tests
        self.options = Options()
        self.options.add_argument("--headless")
        self.driver = webdriver.Chrome('chromedriver', chrome_options=self.options)
        # Allow a little time for the driver to initialize
        self.driver.implicitly_wait(30)
        # Set the base address of the dojo
        self.base_url = "http://localhost:8080/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        # Make a member reference to the driver
        driver = self.driver
        # Navigate to the login page
        driver.get(self.base_url + "login")
        # Good practice to clear the entry before typing
        driver.find_element_by_id("id_username").clear()
        # These credentials will be used by Travis when testing new PRs
        # They will not work when testing on your own build
        # Be sure to change them before submitting a PR
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        # "Click" the but the login button
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_create_user(self):
        # Login to the site.
        driver = self.login_page()
        # Navigate to the User managegement page
        driver.get(self.base_url + "user")
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the add prodcut button
        driver.find_element_by_link_text("New User").click()
        # Fill in the Necessary User Details
        # username, first name, last name, email, and permissions
        # Don't forget to clear before inserting
        # username
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys("propersahm")
        # First Name
        driver.find_element_by_id("id_first_name").clear()
        driver.find_element_by_id("id_first_name").send_keys("Proper")
        # Last Name
        driver.find_element_by_id("id_last_name").clear()
        driver.find_element_by_id("id_last_name").send_keys("Samuel")
        # Email Address
        driver.find_element_by_id("id_email").clear()
        driver.find_element_by_id("id_email").send_keys("propersam@example.com")
        # Give user super user permissions by ticking the checkbox 'is_superuser'
        driver.find_element_by_name("is_superuser").click()  # Clicking will mark the checkbox
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the user has been created
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'User added successfully, you may edit if necessary.', productTxt) or
            re.search(r'A user with that username already exists.', productTxt))

    def test_user_edit_permissions(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to User Management page
        driver.get(self.base_url + "user")
        # Select the previously created user to edit
        # The User name is not clickable
        # so we would have to select specific user by filtering list of users
        driver.find_element_by_id("show-filters").click()  # open d filters
        # Insert username to filter by into user name box
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys("propersahm")
        # click on 'apply filter' button
        driver.find_element_by_css_selector("button.btn.btn-sm.btn-primary").click()
        # only the needed user is now available proceed with clicking 'Edit' button
        driver.find_element_by_link_text("Edit").click()
        # Unselect Super Admin Permission from previously created user
        # and only select Staff Permission
        driver.find_element_by_name("is_superuser").click()
        driver.find_element_by_name("is_staff").click()
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the User permission has been changed
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'User saved successfully.', productTxt))

    def test_user_delete(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "user")
        # Select A user to edit
        # The User name is not clickable
        # so we would have to select specific user by filtering list of users
        driver.find_element_by_id("show-filters").click()  # open d filters
        # Insert username to filter by into user name box
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys("propersahm")
        # click on 'apply filter' button
        driver.find_element_by_css_selector("button.btn.btn-sm.btn-primary").click()
        # only the needed user is now available proceed with clicking 'Edit' button
        driver.find_element_by_link_text("Edit").click()
        # "Click" the delete button to complete the transaction
        driver.find_element_by_css_selector("a.btn.btn-danger").click()
        # confirm deletion, by clicking delete a second time
        driver.find_element_by_css_selector("button.btn.btn-danger").click()
        # Query the site to determine if the User has been deleted
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'User and relationships removed.', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(UserTest('test_create_user'))
    suite.addTest(UserTest('test_user_edit_permissions'))
    suite.addTest(UserTest('test_user_delete'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
