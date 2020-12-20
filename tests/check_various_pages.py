import unittest
from base_test_class import BaseTestCase


class Login(BaseTestCase):
    def test_user_status(self):
        driver = self.driver
        driver.get(self.base_url + "user")

    def test_calendar_status(self):
        driver = self.driver
        driver.get(self.base_url + "calendar")


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(ProductTest('test_user_status'))
    suite.addTest(ProductTest('test_calendar_status'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
