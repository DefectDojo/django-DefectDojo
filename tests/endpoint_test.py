from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import unittest
import sys
from base_test_class import BaseTestCase
from product_test import ProductTest


class EndpointTest(BaseTestCase):

    def test_create_endpoint(self):
        # Login to the site.
        # Username and password will be gotten from environ
        driver = self.driver
        # Navigate to the Endpoint page
        driver.get(self.base_url + "endpoint")
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the New Endpoint
        driver.find_element(By.LINK_TEXT, "New Endpoint").click()
        # Keep a good practice of clearing field before entering value
        # Endpoints
        driver.find_element(By.ID, "id_endpoint").clear()
        driver.find_element(By.ID, "id_endpoint").send_keys("moving.com.rnd")
        # Select product to assign endpoint to
        Select(driver.find_element(By.ID, "id_product")).select_by_visible_text("QA Test")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Endpoint added successfully'))

    def test_edit_endpoint(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the endpoint page
        driver.get(self.base_url + "endpoint")
        # Select one of the previously created endpoint to edit
        driver.find_element(By.LINK_TEXT, "moving.com.rnd").click()
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the Edit Endpoint
        driver.find_element(By.LINK_TEXT, "Edit Endpoint").click()
        # Clear the old endpoint host name
        driver.find_element(By.ID, "id_host").clear()
        # Fill in the endpoint host name
        driver.find_element(By.ID, "id_host").send_keys("rnd.moving.com")
        # Fill in port for endpoint
        driver.find_element(By.ID, "id_port").clear()
        driver.find_element(By.ID, "id_port").send_keys("8080")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the product has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Endpoint updated successfully'))

    def test_delete_endpoint(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the endpoint page
        driver.get(self.base_url + "endpoint")
        # Select one of the previously created endpoint to delete
        driver.find_element(By.LINK_TEXT, "rnd.moving.com:8080").click()
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the Delete Endpoint
        driver.find_element(By.LINK_TEXT, "Delete Endpoint").click()
        # "Click" the delete button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()
        # Query the site to determine if the product has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text='Endpoint and relationships removed.'))


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(BaseTestCase('disable_block_execution'))
    suite.addTest(ProductTest('test_create_product'))
    suite.addTest(EndpointTest('test_create_endpoint'))
    suite.addTest(EndpointTest('test_edit_endpoint'))
    suite.addTest(EndpointTest('test_delete_endpoint'))
    suite.addTest(ProductTest('test_delete_product'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
