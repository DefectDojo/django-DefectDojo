from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
import os


# first thing first. We have to create product, just to make sure there is atleast 1 product available
# to assign endpoints to when creating or editing any.
# importing Product_unit_test as a module
# set relative path
dir_path = os.path.dirname(os.path.realpath(__file__))
try:  # First Try for python 3
    import importlib.util
    product_unit_test_module = importlib.util.spec_from_file_location("Product_unit_test",
        os.path.join(dir_path, 'Product_unit_test.py'))  # using ',' allows python to determine the type of separator to use.
    product_unit_test = importlib.util.module_from_spec(product_unit_test_module)
    product_unit_test_module.loader.exec_module(product_unit_test)
except:  # This will work for python2 if above fails
    import imp
    product_unit_test = imp.load_source('Product_unit_test',
        os.path.join(dir_path, 'Product_unit_test.py'))


class TestUnitTest(unittest.TestCase):
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

    def test_create_test(self):
        # To create test for a product
        # You must have an engagement and then tests are packed in engagements
        # Login to the site.
        # Username and password will be gotten from environ
        driver = self.login_page()
        # Navigate to the Product page to select the product we created earlier
        driver.get(self.base_url + "product")
        # Select and click on the particular product to create test for
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on the 'Engagement' Dropdown button
        driver.find_element_by_partial_link_text("Engagement").click()
        # 'click' the Add New Engagement option
        driver.find_element_by_link_text("Add New Engagement").click()
        # Keep a good practice of clearing field before entering value
        # fill up at least all required input field options.
        # fields: 'Name', 'Description', 'Target Start', 'Target End', 'Testing Lead' and 'Status'
        # engagement name
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Beta Test")
        # engagement description
        # Tab into the description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element_by_id("id_name").send_keys("\tRunning Test on product before approving and push to production.")
        # engagement target start and target end already have defaults
        # we can safely skip
        # Testing Lead: This can be the logged in user
        Select(driver.find_element_by_id("id_lead")).select_by_visible_text('admin')
        # engagement status
        Select(driver.find_element_by_id("id_status")).select_by_visible_text("In Progress")
        # "Click" the 'Add Test' button to Add Test to engagement
        driver.find_element_by_name("_Add Tests").click()
        # Fill at least required fields needed to create Test
        # Test title
        driver.find_element_by_id("id_title").clear()  # clear field before inserting anything
        driver.find_element_by_id("id_title").send_keys("Quick Security Testing")
        # Select Test type
        Select(driver.find_element_by_id("id_test_type")).select_by_visible_text("Manual Code Review")
        # skip Target start and Target end leaving their default values
        # Select Testing Environment
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Development")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the Test has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert on the query to determine success or failure
        self.assertTrue(re.search(r'Test added successfully', productTxt))

    def test_edit_test(self):
        # Login to the site.
        driver = self.login_page()
        # Navigate to the engagement page
        driver.get(self.base_url + "engagement")
        # Select a previously created engagement title
        driver.find_element_by_partial_link_text("Quick Security Testing").click()
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the Edit Test option
        driver.find_element_by_link_text("Edit Test").click()
        # Change Testing Environment to Staging from Development
        Select(driver.find_element_by_id("id_environment")).select_by_visible_text("Staging")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the Test has been updated
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Test saved.', productTxt))

    def test_add_note(self):
        # Login to the site.
        driver = self.login_page()
        # Navigate to the engagement page
        driver.get(self.base_url + "engagement")
        # Select a previously created engagement title
        driver.find_element_by_partial_link_text("Quick Security Testing").click()
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the Edit Test option
        driver.find_element_by_link_text("Add Notes").click()
        # Select entry, clear field and input note
        driver.find_element_by_id("id_entry").clear()
        driver.find_element_by_id("id_entry").send_keys("This is a sample note for all to see.")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_xpath("//input[@value='Add Note']").click()
        # Query the site to determine if the Test has been updated
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Note added successfully.', productTxt))

    def test_delete_test(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the engagement page
        driver.get(self.base_url + "engagement")
        # Select a previously created engagement title
        driver.find_element_by_partial_link_text("Quick Security Testing").click()
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the Edit Test option
        driver.find_element_by_link_text("Delete Test").click()
        # Type test name into Title field before clicking Delet button
        driver.find_element_by_id("id_title").clear()  # always clear for inputting
        driver.find_element_by_id("id_title").send_keys("Quick Security Testing")
        # "Click" the delete button to complete the transaction
        driver.find_element_by_css_selector("button.btn.btn-danger").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Test and relationships removed.', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(product_unit_test.ProductTest('test_create_product'))
    suite.addTest(TestUnitTest('test_create_test'))
    suite.addTest(TestUnitTest('test_edit_test'))
    # suite.addTest(TestUnitTest('test_add_note'))
    # suite.addTest(TestUnitTest('test_delete_test'))
    suite.addTest(product_unit_test.ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
