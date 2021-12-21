import unittest
import sys

from base_test_class import BaseTestCase
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import ActionChains
from selenium.common.exceptions import NoSuchElementException


class NotificationTest(BaseTestCase):

    def enable_notification(self, type):
        driver = self.driver
        # Navigate to the System Settimgs
        driver.get(self.base_url + "system_settings")
        mail_control = driver.find_element(By.ID, "id_enable_{}_notifications".format(type))
        if not mail_control.is_selected():
            mail_control.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def disable_notification(self, type):
        driver = self.driver
        # Navigate to the System Settimgs
        driver.get(self.base_url + "system_settings")
        mail_control = driver.find_element(By.ID, "id_enable_{}_notifications".format(type))
        if mail_control.is_selected():
            mail_control.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def test_disable_mail_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.disable_notification('mail')
        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']")
            assert False
        except NoSuchElementException:
            assert True

    def test_disable_slack_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.disable_notification("slack")

        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='slack']")
            assert False
        except NoSuchElementException:
            assert True

    def test_disable_msteams_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.disable_notification("msteams")

        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='msteams']")
            assert False
        except NoSuchElementException:
            assert True

    def test_enable_mail_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.enable_notification('mail')
        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']")
            assert True
        except NoSuchElementException:
            assert False

    def test_enable_slack_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.enable_notification("slack")

        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='slack']")
            assert True
        except NoSuchElementException:
            assert False

    def test_enable_msteams_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.enable_notification("msteams")

        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='msteams']")
            assert False
        except NoSuchElementException:
            assert True

    def test_user_mail_notifications_change(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        wait = WebDriverWait(driver, 5)
        actions = ActionChains(driver)
        configuration_menu = driver.find_element(By.ID, 'menu_configuration')
        actions.move_to_element(configuration_menu).perform()
        wait.until(EC.visibility_of_element_located((By.LINK_TEXT, "Notifications"))).click()

        originally_selected = {
            'product_added': driver.find_element(By.XPATH,
                                                 "//input[@name='product_added' and @value='mail']").is_selected(),
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


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(NotificationTest('test_disable_mail_notification'))
    suite.addTest(NotificationTest('test_disable_slack_notification'))
    suite.addTest(NotificationTest('test_disable_msteams_notification'))
    suite.addTest(NotificationTest('test_enable_mail_notification'))
    suite.addTest(NotificationTest('test_enable_slack_notification'))
    suite.addTest(NotificationTest('test_enable_msteams_notification'))
    # not really for the user we created, but still related to user settings
    suite.addTest(NotificationTest('test_user_mail_notifications_change'))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
