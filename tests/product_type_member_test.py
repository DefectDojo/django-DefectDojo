import logging
import sys
import unittest

from base_test_class import BaseTestCase
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import Select, WebDriverWait
from user_test import UserTest

logger = logging.getLogger(__name__)


class ProductTypeMemberTest(BaseTestCase):

    """Legacy authorization: product types use authorized_users (no roles)."""

    def test_user_add_product_type_member(self):
        driver = self.driver
        driver.get(self.base_url + "user")
        driver.find_element(By.LINK_TEXT, "propersahm").click()
        if not self.is_element_by_id_present("dropdownMenuAddProductTypeMember"):
            logger.info("test_user_add_product_type_member: dropdown not present, skipping")
            return
        driver.find_element(By.ID, "dropdownMenuAddProductTypeMember").click()
        driver.find_element(By.ID, "addProductTypeMember").click()
        try:
            WebDriverWait(driver, 5).until(expected_conditions.presence_of_element_located((By.ID, "id_product_types")))
        except TimeoutException:
            self.fail("Timed out waiting for product types dropdown to initialize ")
        driver.execute_script("document.getElementsByName('product_types')[0].style.display = 'inline'")
        element = driver.find_element(By.XPATH, "//select[@name='product_types']")
        product_type_option = element.find_elements(By.TAG_NAME, "option")[0]
        Select(element).select_by_value(product_type_option.get_attribute("value"))
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(self.is_success_message_present(text="Authorized propersahm"))
        # Verify Research and Development is now listed in the user's accessible product types
        member_pts = [e.text for e in driver.find_elements(By.NAME, "member_product_type")]
        self.assertIn("Research and Development", member_pts)

    def test_user_delete_product_type_member(self):
        driver = self.driver
        driver.get(self.base_url + "user")
        driver.find_element(By.LINK_TEXT, "propersahm").click()
        if not self.is_element_by_id_present("dropdownMenuAddProductTypeMember"):
            logger.info("test_user_delete_product_type_member: dropdown not present, skipping")
            return
        # Directly submit the hidden revoke form (bypass confirm dialog)
        revoke_form = driver.find_element(By.CSS_SELECTOR, "form[id^='revoke-product-type-']")
        form_id = revoke_form.get_attribute("id")
        driver.execute_script(f"document.getElementById('{form_id}').submit();")
        self.assertTrue(self.is_success_message_present(text="Revoked propersahm"))
        self.assertFalse(driver.find_elements(By.NAME, "member_product_type"))

    def test_product_type_add_product_type_member(self):
        driver = self.driver
        driver.get(self.base_url + "product/type")
        driver.find_element(By.ID, "dropdownMenuProductType").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "View").click()
        if not self.is_element_by_id_present("dropdownMenuAddAuthorizedUsers"):
            logger.info("test_product_type_add_product_type_member: dropdown not present, skipping")
            return
        driver.find_element(By.ID, "dropdownMenuAddAuthorizedUsers").click()
        driver.find_element(By.ID, "addAuthorizedUser").click()
        try:
            WebDriverWait(driver, 5).until(expected_conditions.presence_of_element_located((By.ID, "id_users")))
        except TimeoutException:
            self.fail("Timed out waiting for users dropdown to initialize ")
        driver.execute_script("document.getElementsByName('users')[0].style.display = 'inline'")
        element = driver.find_element(By.XPATH, "//select[@name='users']")
        propersahm_option = None
        for option in element.find_elements(By.TAG_NAME, "option"):
            if "propersahm" in option.text:
                propersahm_option = option
                break
        self.assertIsNotNone(propersahm_option, "propersahm option not found in users select")
        Select(element).select_by_value(propersahm_option.get_attribute("value"))
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        self.assertTrue(self.is_success_message_present(text="Added 1 user(s) to authorized users."))
        usernames = [e.text for e in driver.find_elements(By.NAME, "authorized_user_username")]
        self.assertIn("propersahm", usernames)

    def test_product_type_delete_product_type_member(self):
        driver = self.driver
        driver.get(self.base_url + "product/type")
        driver.find_element(By.ID, "dropdownMenuProductType").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "View").click()
        if not self.is_element_by_id_present("dropdownMenuAddAuthorizedUsers"):
            logger.info("test_product_type_delete_product_type_member: dropdown not present, skipping")
            return
        # Find the propersahm row's remove-authorized-user form and submit it
        usernames = driver.find_elements(By.NAME, "authorized_user_username")
        propersahm_row = None
        for u in usernames:
            if u.text == "propersahm":
                propersahm_row = u.find_element(By.XPATH, "./..")
                break
        self.assertIsNotNone(propersahm_row, "propersahm not found in authorized users list")
        remove_form = propersahm_row.find_element(By.CSS_SELECTOR, "form[id^='remove-authorized-user-']")
        form_id = remove_form.get_attribute("id")
        driver.execute_script(f"document.getElementById('{form_id}').submit();")
        self.assertTrue(self.is_success_message_present(text="Removed propersahm from authorized users."))
        usernames_after = [e.text for e in driver.find_elements(By.NAME, "authorized_user_username")]
        self.assertNotIn("propersahm", usernames_after)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(BaseTestCase("disable_block_execution"))
    suite.addTest(UserTest("test_create_user"))
    suite.addTest(ProductTypeMemberTest("test_user_add_product_type_member"))
    suite.addTest(ProductTypeMemberTest("test_user_delete_product_type_member"))
    suite.addTest(ProductTypeMemberTest("test_product_type_add_product_type_member"))
    suite.addTest(ProductTypeMemberTest("test_product_type_delete_product_type_member"))
    suite.addTest(UserTest("test_user_delete"))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
