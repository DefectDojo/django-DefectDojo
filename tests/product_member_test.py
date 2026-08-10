import logging
import sys
import unittest

from base_test_class import BaseTestCase
from product_test import ProductTest
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import Select, WebDriverWait
from user_test import UserTest

logger = logging.getLogger(__name__)


class ProductMemberTest(BaseTestCase):

    """Legacy authorization: products use authorized_users (no roles)."""

    def test_user_add_product_member(self):
        driver = self.driver
        driver.get(self.base_url + "user")
        driver.find_element(By.LINK_TEXT, "propersahm").click()
        if not self.is_element_by_id_present("dropdownMenuAddProductMember"):
            logger.info("test_user_add_product_member: dropdown not present, skipping")
            return
        driver.find_element(By.ID, "dropdownMenuAddProductMember").click()
        driver.find_element(By.ID, "addProductMember").click()
        try:
            WebDriverWait(driver, 5).until(expected_conditions.presence_of_element_located((By.ID, "id_products")))
        except TimeoutException:
            self.fail("Timed out waiting for products dropdown to initialize ")
        driver.execute_script("document.getElementsByName('products')[0].style.display = 'inline'")
        element = driver.find_element(By.XPATH, "//select[@name='products']")
        product_option = element.find_elements(By.TAG_NAME, "option")[0]
        Select(element).select_by_value(product_option.get_attribute("value"))
        # Submit (legacy auth does not use a role field)
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(self.is_success_message_present(text="Authorized propersahm"))
        # Verify QA Test is now listed in the user's accessible products
        self.assertEqual(driver.find_elements(By.NAME, "member_product")[0].text, "QA Test")

    def test_user_delete_product_member(self):
        driver = self.driver
        driver.get(self.base_url + "user")
        driver.find_element(By.LINK_TEXT, "propersahm").click()
        if not self.is_element_by_id_present("dropdownMenuAddProductMember"):
            logger.info("test_user_delete_product_member: dropdown not present, skipping")
            return
        # Open the per-product actions dropdown and click Revoke.
        # The revoke link uses a confirm() dialog and a hidden form submit;
        # bypass the confirm by directly submitting the hidden form.
        revoke_form = driver.find_element(By.CSS_SELECTOR, "form[id^='revoke-product-']")
        form_id = revoke_form.get_attribute("id")
        driver.execute_script(f"document.getElementById('{form_id}').submit();")
        self.assertTrue(self.is_success_message_present(text="Revoked propersahm"))
        self.assertFalse(driver.find_elements(By.NAME, "member_product"))

    def test_product_add_product_member(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        if not self.is_element_by_id_present("dropdownMenuAddAuthorizedUsers"):
            logger.info("test_product_add_product_member: dropdown not present, skipping")
            return
        driver.find_element(By.ID, "dropdownMenuAddAuthorizedUsers").click()
        driver.find_element(By.ID, "addAuthorizedUser").click()
        try:
            WebDriverWait(driver, 5).until(expected_conditions.presence_of_element_located((By.ID, "id_users")))
        except TimeoutException:
            self.fail("Timed out waiting for users dropdown to initialize ")
        driver.execute_script("document.getElementsByName('users')[0].style.display = 'inline'")
        element = driver.find_element(By.XPATH, "//select[@name='users']")
        # Find the propersahm option specifically
        propersahm_option = None
        for option in element.find_elements(By.TAG_NAME, "option"):
            if "propersahm" in option.text:
                propersahm_option = option
                break
        self.assertIsNotNone(propersahm_option, "propersahm option not found in users select")
        Select(element).select_by_value(propersahm_option.get_attribute("value"))
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(self.is_success_message_present(text="Added 1 user(s) to authorized users."))
        # Verify propersahm is now listed in the product's authorized users
        usernames = [e.text for e in driver.find_elements(By.NAME, "authorized_user_username")]
        self.assertIn("propersahm", usernames)

    def test_product_delete_product_member(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        if not self.is_element_by_id_present("dropdownMenuAddAuthorizedUsers"):
            logger.info("test_product_delete_product_member: dropdown not present, skipping")
            return
        # Directly submit the hidden remove-authorized-user form (bypass confirm dialog)
        remove_form = driver.find_element(By.CSS_SELECTOR, "form[id^='remove-authorized-user-']")
        form_id = remove_form.get_attribute("id")
        driver.execute_script(f"document.getElementById('{form_id}').submit();")
        self.assertTrue(self.is_success_message_present(text="Removed propersahm from authorized users."))
        usernames = [e.text for e in driver.find_elements(By.NAME, "authorized_user_username")]
        self.assertNotIn("propersahm", usernames)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(BaseTestCase("disable_block_execution"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(UserTest("test_create_user"))
    suite.addTest(ProductMemberTest("test_user_add_product_member"))
    suite.addTest(ProductMemberTest("test_user_delete_product_member"))
    suite.addTest(ProductMemberTest("test_product_add_product_member"))
    suite.addTest(ProductMemberTest("test_product_delete_product_member"))
    suite.addTest(UserTest("test_user_delete"))
    suite.addTest(ProductTest("test_delete_product"))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
