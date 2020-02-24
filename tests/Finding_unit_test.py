from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.keys import Keys
import unittest
import re
import sys
import os

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


class FindingTest(unittest.TestCase):
    def setUp(self):
        self.options = Options()
        self.options.add_argument("--headless")
        # self.options.add_argument("--no-sandbox")
        # self.options.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome('chromedriver', chrome_options=self.options)
        self.driver.implicitly_wait(30)
        self.base_url = os.environ['DD_BASE_URL']
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

    def test_edit_finding(self):
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Edit Finding`
        driver.find_element_by_link_text("Edit Finding").click()
        # Change: 'Severity' and 'Mitigation'
        # finding Severity
        Select(driver.find_element_by_id("id_severity")).select_by_visible_text("Critical")
        # finding Description
        driver.find_element_by_id("id_severity").send_keys(Keys.TAB, "This is a crucial update to finding description.")
        # "Click" the Done button to Edit the finding
        driver.find_element_by_xpath("//input[@name='_Finished']").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding saved successfully', productTxt))

    def test_add_image(self):
        print("\n\nDebug Print Log: testing 'add image' \n")
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Edit Finding`
        driver.find_element_by_link_text("Manage Images").click()
        # select first file input field: form-0-image
        # Set full image path for image file 'strange.png
        image_path = os.path.join(dir_path, 'finding_image.png')
        driver.find_element_by_id("id_form-0-image").send_keys(image_path)
        # Save uploaded image
        with product_unit_test.WaitForPageLoad(driver, timeout=50):
            driver.find_element_by_css_selector("button.btn.btn-success").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Images updated successfully', productTxt))

    def test_mark_finding_for_review(self):
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Request Peer Reveiw`
        driver.find_element_by_link_text("Request Peer Review").click()
        # select Reviewer
        # Let's make the first user in the list a reviewer
        # set select element style from 'none' to 'inline'
        driver.execute_script("document.getElementsByName('reviewers')[0].style.display = 'inline'")
        # select the first option tag
        element = driver.find_element_by_xpath("//select[@name='reviewers']")
        reviewer_option = element.find_elements_by_tag_name('option')[0]
        Select(element).select_by_value(reviewer_option.get_attribute("value"))
        # Add Review notes
        driver.find_element_by_id("id_entry").clear()
        driver.find_element_by_id("id_entry").send_keys("This is to be reveiwed critically. Make sure it is well handled.")
        # Click 'Mark for reveiw'
        driver.find_element_by_name("submit").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding marked for review and reviewers notified.', productTxt))

    def test_clear_review_from_finding(self):
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on `Clear Review` link text
        driver.find_element_by_link_text("Clear Review").click()
        # Mark Active and Verified checkboxes
        driver.find_element_by_id('id_active').click()
        driver.find_element_by_id('id_verified').click()
        # Add Review notes
        driver.find_element_by_id("id_entry").clear()
        driver.find_element_by_id("id_entry").send_keys("This has been reviewed and confirmed. A fix needed here.")
        # Click 'Clear reveiw' button
        driver.find_element_by_name("submit").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding review has been updated successfully.', productTxt))

    def test_delete_image(self):
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Edit Finding`
        driver.find_element_by_link_text("Manage Images").click()
        # mark delete checkbox for first file input field: form-0-DELETE
        driver.find_element_by_id("id_form-0-DELETE").click()
        # Save selection(s) for image deletion
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Images updated successfully', productTxt))

    def test_close_finding(self):
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Close Finding`
        driver.find_element_by_link_text("Close Finding").click()
        # fill notes stating why finding should be closed
        driver.find_element_by_id("id_entry").send_keys("All issues in this Finding have been resolved successfully")
        # click 'close Finding' submission button
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding closed.', productTxt))

    def test_make_finding_a_template(self):
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Make Finding a Template`
        driver.find_element_by_link_text("Make Finding a Template").click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding template added successfully. You may edit it here.', productTxt) or
            re.search(r'A finding template with that title already exists.', productTxt))

    def test_apply_template_to_a_finding(self):
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Apply Template to Finding`
        driver.find_element_by_link_text("Apply Template to Finding").click()
        # click on the template of 'App Vulnerable to XSS'
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on 'Replace all' button
        driver.find_element_by_xpath("//button[@data-option='Replace']").click()
        # Click the 'finished' button to submit
        driver.find_element_by_name('_Finished').click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'App Vulnerable to XSS', productTxt))

    def test_delete_finding_template(self):
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "template")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on `Delete Template` button
        driver.find_element_by_xpath("//button[text()='Delete Template']").click()
        # Click 'Yes' on Alert popup
        driver.switch_to.alert.accept()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding Template deleted successfully.', productTxt))

    def test_import_scan_result(self):
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'Finding' dropdown menubar
        driver.find_element_by_partial_link_text("Findings").click()
        # Click on `Import Scan Results` link text
        driver.find_element_by_link_text("Import Scan Results").click()
        # Select `ZAP Scan' as Scan Type
        Select(driver.find_element_by_id("id_scan_type")).select_by_visible_text('ZAP Scan')
        # upload scan file
        file_path = os.path.join(dir_path, 'zap_sample.xml')
        driver.find_element_by_name("file").send_keys(file_path)
        # Click Submit button
        with product_unit_test.WaitForPageLoad(driver, timeout=50):
            driver.find_elements_by_css_selector("button.btn.btn-primary")[1].click()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        print("\n\nDebug Print Log: findingTxt fetched: {}\n".format(productTxt))
        print("Checking for '.*ZAP Scan processed, a total of 4 findings were processed.*'")
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'ZAP Scan processed, a total of 4 findings were processed', productTxt))

    def test_delete_finding(self):
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.login_page()
        # Navigate to All Finding page
        driver.get(self.base_url + "finding")
        # Select and click on the particular finding to edit
        driver.find_element_by_link_text("App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element_by_id("dropdownMenu1").click()
        # Click on `Delete Finding`
        driver.find_element_by_link_text("Delete Finding").click()
        # Click 'Yes' on Alert popup
        driver.switch_to.alert.accept()
        # Query the site to determine if the finding has been added
        productTxt = driver.find_element_by_tag_name("BODY").text
        # Assert ot the query to dtermine status of failure
        self.assertTrue(re.search(r'Finding deleted successfully', productTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(product_unit_test.ProductTest('test_create_product'))
    suite.addTest(product_unit_test.ProductTest('test_add_product_finding'))
    suite.addTest(FindingTest('test_edit_finding'))
    suite.addTest(FindingTest('test_add_image'))
    suite.addTest(FindingTest('test_mark_finding_for_review'))
    suite.addTest(FindingTest('test_clear_review_from_finding'))
    suite.addTest(FindingTest('test_close_finding'))
    suite.addTest(FindingTest('test_make_finding_a_template'))
    suite.addTest(FindingTest('test_apply_template_to_a_finding'))
    suite.addTest(FindingTest('test_import_scan_result'))
    suite.addTest(FindingTest('test_delete_image'))
    suite.addTest(FindingTest('test_delete_finding'))
    suite.addTest(FindingTest('test_delete_finding_template'))
    suite.addTest(product_unit_test.ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
