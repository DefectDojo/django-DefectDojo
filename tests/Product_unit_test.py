from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.keys import Keys
import unittest
import re
import sys
import os
import time


class WaitForPageLoad(object):
    def __init__(self, browser, timeout):
        self.browser = browser
        self.timeout = time.time() + timeout

    def __enter__(self):
        self.old_page = self.browser.find_element_by_tag_name('html')

    def page_has_loaded(self):
        new_page = self.browser.find_element_by_tag_name('html')
        return new_page.id != self.old_page.id

    def __exit__(self, *_):
        while time.time() < self.timeout:
            if self.page_has_loaded():
                return True
            else:
                time.sleep(0.2)
        raise Exception(
            'Timeout waiting for {}s'.format(self.timeout)
        )


class ProductTest(unittest.TestCase):
    def setUp(self):
        self.options = Options()
        self.options.add_argument("--headless")  # Comment out this line to allow test run with browser visible
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
        # Set the user to an admin account
        # os.environ['DD_ADMIN_USER']
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        # "Click" the but the login button
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_create_product(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the add prodcut button
        driver.find_element_by_link_text("Add Product").click()
        # Fill in th product name
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("QA Test")
        # Tab into the description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element_by_id("id_name").send_keys("\tThis is just a test. Be very afraid.")
        # Select an option in the poroduct type
        Select(driver.find_element_by_id("id_prod_type")).select_by_visible_text("Research and Development")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        # Also confirm success even if Product is returned as already exists for test sake
        self.assertTrue(re.search(r'Product added successfully', productTxt) or
            re.search(r'Product with this Name already exists.', productTxt))

    # For product consistency sake, We won't be editting the product title
    # instead We can edit the product description
    def test_edit_product_description(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on the 'Edit' option
        driver.find_element_by_link_text("Edit").click()
        # Edit product description
        driver.find_element_by_id("id_name").send_keys(Keys.TAB, "Updated Desription: ")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Product updated successfully', productTxt) or
            re.search(r'Product with this Name already exists.', productTxt))

    def test_add_product_engagement(self):
        # Test To Add Engagement To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on the 'Engagement dropdown button'
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
        driver.find_element_by_id("id_name").send_keys(Keys.TAB, "Running Test on product before approving and push to production.")
        # engagement target start and target end already have defaults
        # we can safely skip
        # Testing Lead: This can be the logged in user
        Select(driver.find_element_by_id("id_lead")).select_by_visible_text('admin')
        # engagement status
        Select(driver.find_element_by_id("id_status")).select_by_visible_text("In Progress")
        # "Click" the Done button to Add the engagement
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert of the query to dtermine status of failure
        self.assertTrue(re.search(r'Engagement added successfully', productTxt))

    def test_add_product_finding(self):
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # Click on the 'Finding dropdown button'
        driver.find_element_by_partial_link_text("Findings").click()
        # Click on `Add New Finding`
        driver.find_element_by_link_text("Add New Finding").click()
        # Keep a good practice of clearing field before entering value
        # fill up at least all required input field options.
        # fields: 'Title', 'Date', 'Severity', 'Description', 'Mitigation' and 'Impact'
        # finding Title
        driver.find_element_by_id("id_title").clear()
        driver.find_element_by_id("id_title").send_keys("App Vulnerable to XSS")
        # finding Date as a default value and can be safely skipped
        # finding Severity
        Select(driver.find_element_by_id("id_severity")).select_by_visible_text("High")
        # finding Description
        driver.find_element_by_id("id_severity").send_keys(Keys.TAB, "This is just a Test Case Finding")
        # Finding Mitigation
        # Use Javascript to bypass the editor by making Setting textArea style from none to inline
        # Any Text written to textarea automatically reflects in Editor field.
        driver.execute_script("document.getElementsByName('mitigation')[0].style.display = 'inline'")
        driver.find_element_by_name("mitigation").send_keys(Keys.TAB, "How to mitigate this finding")
        # Finding Impact
        # Use Javascript to bypass the editor by making Setting textArea style from none to inline
        # Any Text written to textarea automatically reflects in Editor field.
        driver.execute_script("document.getElementsByName('impact')[0].style.display = 'inline'")
        driver.find_element_by_name("impact").send_keys(Keys.TAB, "This has a very critical effect on production")
        # "Click" the Done button to Add the finding with other defaults
        with WaitForPageLoad(driver, timeout=30):
            driver.find_element_by_xpath("//input[@name='_Finished']").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert to the query to dtermine status of failure
        self.assertTrue(re.search(r'App Vulnerable to XSS', productTxt))

    def test_add_product_endpoints(self):
        # Test To Add Endpoints To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # Click on the 'Endpoints' dropdown button
        driver.find_element_by_partial_link_text("Endpoints").click()
        # 'click' the Add New Endpoint option
        driver.find_element_by_link_text("Add New Endpoint").click()
        # Keep a good practice of clearing field before entering value
        # Endpoints
        driver.find_element_by_id("id_endpoint").clear()
        driver.find_element_by_id("id_endpoint").send_keys("strange.prod.dev\n123.45.6.30")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Endpoint added successfully', productTxt))

    def test_add_product_custom_field(self):
        # Test To Add Custom Fields To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # 'click' the Add Custom Fields
        driver.find_element_by_link_text("Add Custom Fields").click()
        # Keep a good practice of clearing field before entering value
        # Custom Name
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Security Level")
        # Custom Value
        driver.find_element_by_id("id_value").clear()
        driver.find_element_by_id("id_value").send_keys("Loose")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        # Also confirm success even if variable is returned as already exists for test sake
        self.assertTrue(re.search(r'Metadata added successfully', productTxt) or
            re.search(r'A metadata entry with the same name exists already for this object.', productTxt))

    def test_edit_product_custom_field(self):
        # Test To Edit Product Custom Fields
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # 'click' the Edit Custom Fields
        driver.find_element_by_link_text("Edit Custom Fields").click()
        # Keep a good practice of clearing field before entering value
        # Edit Custom Value of First field
        driver.find_element_by_xpath("//input[@value='Loose']").clear()
        driver.find_element_by_xpath("//input[@value='Loose']").send_keys("Strong")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine success or failure
        self.assertTrue(re.search(r'Metadata edited successfully', productTxt) or
            re.search(r'A metadata entry with the same name exists already for this object.', productTxt))

    def test_add_product_tracking_files(self):
        # Test To Add tracking files To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # 'click' the Add Product Tracking Files
        driver.find_element_by_link_text("Add Product Tracking Files").click()
        # Keep a good practice of clearing field before entering value
        # Just fill up to main required fields: 'File path' nd 'review status'
        # Full File path
        driver.find_element_by_id("id_path").clear()
        driver.find_element_by_id("id_path").send_keys("/strange/folder/")
        # REview Status
        Select(driver.find_element_by_id("id_review_status")).select_by_visible_text("Untracked")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Added Tracked File to a Product', productTxt))

    def test_edit_product_tracking_files(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # Select and click on the particular product to edit
        driver.find_element_by_link_text("QA Test").click()
        # "Click" the dropdown option
        driver.find_element_by_id("dropdownMenu1").click()
        # 'click' the Edit Product Tracking Files
        driver.find_element_by_link_text("View Product Tracking Files").click()
        # Keep a good practice of clearing field before entering value
        # Edit Custom Value of First field
        driver.find_element_by_link_text("Edit").click()
        # Edit full file path
        driver.find_element_by_id("id_path").clear()
        driver.find_element_by_id("id_path").send_keys("/unknown/folder/")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the Tracking file has been updated
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Tool Product Configuration Successfully Updated', productTxt))

    def test_delete_product(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # Select the specific product to delete
        driver.find_element_by_link_text("QA Test").click()
        # Click the drop down menu
        driver.find_element_by_id('dropdownMenu1').click()
        # "Click" the Delete option
        driver.find_element_by_link_text("Delete").click()
        # "Click" the delete button to complete the transaction
        driver.find_element_by_css_selector("button.btn.btn-danger").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Product and relationships removed.', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    # Add each test and the suite to be run
    # success and failure is output by the test
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(ProductTest('test_edit_product_description'))
    suite.addTest(ProductTest('test_add_product_engagement'))
    suite.addTest(ProductTest('test_add_product_finding'))
    suite.addTest(ProductTest('test_add_product_endpoints'))
    suite.addTest(ProductTest('test_add_product_custom_field'))
    suite.addTest(ProductTest('test_edit_product_custom_field'))
    suite.addTest(ProductTest('test_add_product_tracking_files'))
    suite.addTest(ProductTest('test_edit_product_tracking_files'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
