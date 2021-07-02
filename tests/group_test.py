import unittest
import sys
from base_test_class import BaseTestCase


class GroupTest(BaseTestCase):

    def test_create_group(self):
        # Login to the site.
        driver = self.driver
        # Navigate to the Group managegement page
        driver.get(self.base_url + "group")
        # "Click" the dropdown button to see options
        driver.find_element_by_id("dropdownMenu1").click()
        # "Click" the add group button
        driver.find_element_by_link_text("New Group").click()
        # Fill in the Necessary group Details
        # name
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Group Name")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()
        # Assert status is success
        self.assertTrue(self.is_success_message_present(text='Group was added successfully.'))

    def test_group_edit_name(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to Group Management page
        driver.get(self.base_url + "group")
        # Select the previously created group to edit
        # The name is not clickable
        # so we would have to select specific group by filtering list of groups
        driver.find_element_by_id("show-filters").click()
        # Insert name to filter by into name box
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Group Name")
        # click on 'apply filter' button
        driver.find_element_by_css_selector("button.btn.btn-sm.btn-primary").click()
        # only the needed group is now available, proceed with opening the context menu and clicking 'Edit' button
        driver.find_element_by_id("dropdownMenuGroup").click()
        driver.find_element_by_id("editGroup").click()
        # Edit name
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Another Name")
        # "Click" the submit button to complete the transaction
        driver.find_element_by_css_selector("input.btn.btn-primary").click()

        # Assert status is success
        self.assertTrue(self.is_success_message_present(text='Group saved successfully.'))

    def test_group_delete(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the Group management page
        driver.get(self.base_url + "group")
        # Select the previously created group to edit
        # The name is not clickable
        # so we would have to select specific group by filtering list of groups
        driver.find_element_by_id("show-filters").click()
        # Insert name to filter by into name box
        driver.find_element_by_id("id_name").clear()
        driver.find_element_by_id("id_name").send_keys("Another Name")
        # click on 'apply filter' button
        driver.find_element_by_css_selector("button.btn.btn-sm.btn-primary").click()
        # only the needed group is now available, proceed with clicking 'Delete' button
        driver.find_element_by_id("dropdownMenuGroup").click()
        driver.find_element_by_id("deleteGroup").click()
        # confirm deletion, by clicking delete a second time
        driver.find_element_by_css_selector("button.btn.btn-danger").click()

        # Assert status is success
        self.assertTrue(self.is_success_message_present(text='Group and relationships successfully removed.'))


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase('test_login'))
    suite.addTest(GroupTest('test_create_group'))
    suite.addTest(GroupTest('test_group_edit_name'))
    suite.addTest(GroupTest('test_group_delete'))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)
