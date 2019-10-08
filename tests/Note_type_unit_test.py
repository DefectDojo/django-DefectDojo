from selenium import webdriver
import unittest
import re
import sys
import os


class NoteTypeTest(unittest.TestCase):
    def setUp(self):
        # change path of chromedriver according to which directory you have chromedriver.
        self.driver = webdriver.Chrome('chromedriver')
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:8000/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element_by_id("id_username").clear()
        driver.find_element_by_id("id_username").send_keys(os.environ['DD_ADMIN_USER'])
        driver.find_element_by_id("id_password").clear()
        driver.find_element_by_id("id_password").send_keys(os.environ['DD_ADMIN_PASSWORD'])
        driver.find_element_by_css_selector("button.btn.btn-success").click()
        return driver

    def test_create_note_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "note_type")
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Add Note Type").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("test note type")
        driver.find_element_by_id("id_description").clear()
        driver.find_element_by_id("id_description").send_keys("Test note type description")
        driver.find_element_by_id("id_is_single").click()
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        NoteTypeTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Note Type added successfully.', NoteTypeTxt))

    def test_edit_note_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "note_type")
        driver.find_element_by_link_text("Edit Note Type").click()
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Edited test note type")
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        NoteTypeTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Note type updated successfully.', NoteTypeTxt))

    def test_disable_note_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "note_type")
        driver.find_element_by_link_text("Disable Note Type").click()
        driver.find_element_by_css_selector("input.btn.btn-danger").click()
        NoteTypeTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Note type Disabled successfully.', NoteTypeTxt))

    def test_enable_note_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "note_type")
        driver.find_element_by_link_text("Enable Note Type").click()
        driver.find_element_by_css_selector("input.btn.btn-success").click()
        NoteTypeTxt = driver.find_element_by_tag_name("BODY").text
        self.assertTrue(re.search(r'Note type Enabled successfully.', NoteTypeTxt))

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(NoteTypeTest('test_create_note_type'))
    suite.addTest(NoteTypeTest('test_edit_note_type'))
    suite.addTest(NoteTypeTest('test_disable_note_type'))
    suite.addTest(NoteTypeTest('test_enable_note_type'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
