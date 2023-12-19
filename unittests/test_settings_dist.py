from .dojo_test_case import DojoTestCase, get_unit_tests_path
import os

basedir = os.path.join(get_unit_tests_path(), '..')


class TestSettingsDist(DojoTestCase):
    def test_file_settingsdistpy(self):
        file = os.path.join(basedir, 'dojo', 'settings', 'settings.dist.py')
        ready_for_test = False
        for line in open(file, "r").readlines():
            strip_newline = line.strip('\n')
            if strip_newline == "}":
                ready_for_test = False
            if ready_for_test is True:
                clearstring = strip_newline.strip(' ').strip(',').split('#')[0]
                if len(clearstring) > 0:
                    scanner_setting = clearstring.split(': ')
                    if scanner_setting[1] == "['unique_id_from_tool']":
                        self.assertTrue(False, "Setting unique_id_from_tool does not make sense as you choose DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL for " + scanner_setting[0])
            if strip_newline == "HASHCODE_FIELDS_PER_SCANNER = {":
                ready_for_test = True
