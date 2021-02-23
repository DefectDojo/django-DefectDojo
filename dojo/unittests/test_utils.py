from dojo.models import IMPORT_CLOSED_FINDING, IMPORT_CREATED_FINDING, IMPORT_REACTIVATED_FINDING, IMPORT_UPDATED_FINDING, Test_Import, Test_Import_Finding_Action
from contextlib import contextmanager
from django.test import TestCase
from dojo.utils import dojo_crypto_encrypt, prepare_for_view
import logging


logger = logging.getLogger(__name__)

TEST_IMPORT_ALL = Test_Import.objects.all()
TEST_IMPORTS = Test_Import.objects.filter(type=Test_Import.IMPORT_TYPE)
TEST_REIMPORTS = Test_Import.objects.filter(type=Test_Import.REIMPORT_TYPE)
TEST_IMPORT_FINDING_ACTION_ALL = Test_Import_Finding_Action.objects.all()
TEST_IMPORT_FINDING_ACTION_CREATED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_CREATED_FINDING)
TEST_IMPORT_FINDING_ACTION_CLOSED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_CLOSED_FINDING)
TEST_IMPORT_FINDING_ACTION_REACTIVATED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_REACTIVATED_FINDING)
TEST_IMPORT_FINDING_ACTION_UPDATED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_UPDATED_FINDING)


class TestUtils(TestCase):
    def test_encryption(self):
        test_input = "Hello World!"
        encrypt = dojo_crypto_encrypt(test_input)
        test_output = prepare_for_view(encrypt)
        self.assertEqual(test_input, test_output)


class assertNumOfModelsCreated():
    def __init__(self, test_case, queryset, num):
        self.test_case = test_case
        self.queryset = queryset
        self.num = num

    def __enter__(self):
        self.initial_model_count = self.queryset.count()
        # logger.debug('initial model count for %s: %i', self.queryset.query, self.initial_model_count)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.final_model_count = self.queryset.count()
        # logger.debug('final model count for %s: %i', self.queryset.query, self.final_model_count)
        created_count = self.final_model_count - self.initial_model_count
        self.test_case.assertEqual(
            created_count, self.num,
            "%i objects created, %i expected. query: %s, first 100 objects: %s" % (
                created_count, self.num, self.queryset.query, self.queryset.all().order_by('-id')[:100]
            )
        )


@contextmanager
def assertTestImportModelsCreated(test_case, imports=0, reimports=0, affected_findings=0,
                                    created=0, closed=0, reactivated=0, updated=0):

    with assertNumOfModelsCreated(test_case, TEST_IMPORTS, num=imports) as ti_import_count, \
            assertNumOfModelsCreated(test_case, TEST_REIMPORTS, num=reimports) as ti_reimport_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_ALL, num=affected_findings) as tifa_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_CREATED, num=created) as tifa_created_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_CLOSED, num=closed) as tifa_closed_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_REACTIVATED, num=reactivated) as tifa_reactivated_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_UPDATED, num=updated) as tifa_updated_count:

        yield (
                ti_import_count,
                ti_reimport_count,
                tifa_count,
                tifa_created_count,
                tifa_closed_count,
                tifa_reactivated_count,
                tifa_updated_count
              )
