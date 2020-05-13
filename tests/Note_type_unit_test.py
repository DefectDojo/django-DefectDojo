import unittest
import re
import sys
from base_test_class import BaseTestCase


class NoteTypeTest(BaseTestCase):

    def test_create_note_type(self):
        driver = self.login_page()
        driver.get(self.base_url + "note_type")
        driver.find_element_by_id("dropdownMenu1").click()
        driver.find_element_by_link_text("Add Note Type").click()
        # driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("test note type")
        # driver.find_element_by_id("id_description").clear()
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


def suite():
    suite = unittest.TestSuite()
    suite.addTest(NoteTypeTest('test_create_note_type'))
    suite.addTest(NoteTypeTest('test_edit_note_type'))
    suite.addTest(NoteTypeTest('test_disable_note_type'))
    suite.addTest(NoteTypeTest('test_enable_note_type'))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
