import unittest
import re
import sys
from base_test_class import BaseTestCase


class ProductTypeTest(BaseTestCase):

    def test_create_product_type(self):
        print("\n\nDebug Print Log: testing 'create product type' \n")
        driver = self.login_page()
        driver.get(self.base_url + "product/type")
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Add Product Type").click()
        # driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("product test type")
        driver.find_element_by_id("id_critical_product").click()
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product type added successfully.', productTxt))

    def test_edit_product_type(self):
        print("\n\nDebug Print Log: testing 'edit product type' \n")
        driver = self.login_page()
        driver.get(self.base_url + "product/type")
        driver.find_element_by_link_text("Edit Product Type").click()
        # driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Edited product test type")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product type updated successfully.', productTxt))

    def test_delete_product_type(self):
        print("\n\nDebug Print Log: testing 'delete product type' \n")
        driver = self.login_page()
        driver.get(self.base_url + "product/type")
        # TODO this assumes the first product_type in the list is the one that we just created (and can safely be deleted)
        driver.find_element_by_link_text("Edit Product Type").click()
        driver.find_element_by_css_selector("input.btn.btn-danger").click()
        productTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Product type Deleted successfully.', productTxt))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(ProductTypeTest('test_create_product_type'))
    suite.addTest(ProductTypeTest('test_edit_product_type'))
    suite.addTest(ProductTypeTest('test_delete_product_type'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
