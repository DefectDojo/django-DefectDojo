from selenium import webdriver
from selenium.webdriver.support.ui import Select
import unittest
import re
import sys
import os


class ProductTest(unittest.TestCase):
    def setUp(self):
        # Initialize the driver
        self.driver = webdriver.Chrome('chromedriver')
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
        driver.find_element_by_id("id_username").send_keys(os.environ['DOJO_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        # Use the password unqiue to the container. Info on finding this below
        # https://github.com/DefectDojo/django-DefectDojo/blob/master/DOCKER.md
        driver.find_element_by_id("id_password").send_keys(os.environ['DOJO_ADMIN_PASSWORD'])
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
        driver.find_element_by_id("id_name").send_keys("QA Test2")
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
        self.assertTrue(re.search(r'Product added successfully', productTxt) or \
             re.search(r'Product with this Name already exists.', productTxt))

    def test_edit_product_title(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
        # "Click" the edit option
        driver.find_element_by_link_text("Edit").click()
        # Clear the old product name
        driver.find_element_by_id("id_name").clear()
        # Fill in the product name
        driver.find_element_by_id("id_name").send_keys("EDITED QA Test")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Product updated successfully', productTxt))
    
    def test_add_product_engagement(self):
        # Test To Add Engagement To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
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
        Select(driver.find_element_by_id("id_lead")).select_by_visible_text(os.environ['DOJO_ADMIN_USER'])
        # engagement status
        Select(driver.find_element_by_id("id_status")).select_by_visible_text("In Progress")
        # "Click" the Done button to Add the engagement
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the product has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Engagement added successfully', productTxt))

    def test_add_product_finding(self):
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
        # 'click' the Add New Engagement option
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
        # Double Tab into the Description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_elements_by_xpath("//div[@class='editor-toolbar']")[1].click().send_keys("\tThis is a very dangerous weakness to this application and really risky indeed.")
        # Finding Mitigation
        # Triple Tab into the Mitigation area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element_by_xpath("//textarea[@name='mitigation']").send_keys("\tProperly Filter out inputs entered into that field.")
        # Finding Impact
        # Tab 4 times to get into the Impact area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_elements_by_css_selector("textarea#req")[3].send_keys("\tThis is a very dangerous weakness to this application and really risky indeed.")
        # "Click" the Done button to Add the finding with other defaults
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Engagement added successfully', productTxt))

    def test_add_product_endpoints(self):
        # Test To Add Endpoints To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
        # 'click' the Add New Endpoint option
        driver.find_element_by_link_text("Add New Endpoint").click()
        # Keep a good practice of clearing field before entering value
        # Endpoints
        driver.find_element_by_id("id_endpoint").clear()
        driver.find_element_by_id("id_endpoint").send_keys("123.22.43.2\nstrange.dir.com\nhttps://anoter.com/strageport")
        # submit
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Endpoint added successfully', productTxt))

    def test_add_product_custom_fields(self):
        # Test To Add Custom Fields To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to Product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
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
        self.assertTrue(re.search(r'Metadata added successfully', productTxt) or \
            re.search(r'A metadata entry with the same name exists already for this object.', productTxt))

    def test_delete_product(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.login_page()
        # Navigate to the product page
        driver.get(self.base_url + "product")
        # "Click" the dropdown option
        driver.find_element_by_class_name("pull-left").click()
        # "Click" the edit option
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
    # suite.addTest(ProductTest('test_create_product'))
    #suite.addTest(ProductTest('test_edit_product_title'))
    # suite.addTest(ProductTest('test_add_product_engagement'))
    # suite.addTest(ProductTest('test_add_product_finding'))
    # suite.addTest(ProductTest('test_add_product_endpoints'))
    suite.addTest(ProductTest('test_add_product_custom_fields'))
    # suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
