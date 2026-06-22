import binascii
import logging
import os
from contextlib import contextmanager
from unittest.mock import Mock, patch

from django.conf import settings

from dojo.location.models import Location
from dojo.models import (
    IMPORT_CLOSED_FINDING,
    IMPORT_CREATED_FINDING,
    IMPORT_REACTIVATED_FINDING,
    IMPORT_UNTOUCHED_FINDING,
    Dojo_User,
    Endpoint,
    Engagement,
    Notifications,
    Product,
    Product_Type,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
)
from dojo.notifications.signals import create_default_notifications
from dojo.utils import dojo_crypto_encrypt, encrypt, get_db_key, prepare_for_save, prepare_for_view

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)

TEST_IMPORT_ALL = Test_Import.objects.all()
TEST_IMPORTS = Test_Import.objects.filter(type=Test_Import.IMPORT_TYPE)
TEST_REIMPORTS = Test_Import.objects.filter(type=Test_Import.REIMPORT_TYPE)
TEST_IMPORT_FINDING_ACTION_ALL = Test_Import_Finding_Action.objects.all()
TEST_IMPORT_FINDING_ACTION_AFFECTED = TEST_IMPORT_FINDING_ACTION_ALL.filter(
    action__in=[IMPORT_CREATED_FINDING, IMPORT_CLOSED_FINDING, IMPORT_REACTIVATED_FINDING])
TEST_IMPORT_FINDING_ACTION_CREATED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_CREATED_FINDING)
TEST_IMPORT_FINDING_ACTION_CLOSED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_CLOSED_FINDING)
TEST_IMPORT_FINDING_ACTION_REACTIVATED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_REACTIVATED_FINDING)
TEST_IMPORT_FINDING_ACTION_UNTOUCHED = TEST_IMPORT_FINDING_ACTION_ALL.filter(action=IMPORT_UNTOUCHED_FINDING)

TESTS = Test.objects.all()
ENGAGEMENTS = Engagement.objects.all()
PRODUCTS = Product.objects.all()
PRODUCT_TYPES = Product_Type.objects.all()
ENDPOINTS = Endpoint.objects.all()
LOCATIONS = Location.objects.all()


class TestUtils(DojoTestCase):
    def test_encryption(self):
        test_input = "Hello World!"
        encrypted = dojo_crypto_encrypt(test_input)
        test_output = prepare_for_view(encrypted)
        self.assertEqual(test_input, test_output)

    def test_encryption_uses_aes2_format(self):
        # New values must be written with the modern AES-256-GCM ("AES.2") scheme.
        encrypted = dojo_crypto_encrypt("some secret")
        self.assertTrue(encrypted.startswith("AES.2:"))

    def test_encryption_roundtrip_variants(self):
        # GCM has no block-size constraint, so cover empty, unicode, and long
        # (multi-block) inputs to be sure padding-free encryption round-trips.
        for value in ["", "ascii-secret", "ünïcödé-pä$$wörd", "x" * 500]:
            with self.subTest(value=value):
                self.assertEqual(value, prepare_for_view(dojo_crypto_encrypt(value)))

    def test_decrypt_legacy_aes1_value(self):
        # Values stored by the legacy AES-256-OFB ("AES.1") scheme must still
        # decrypt unchanged so existing database secrets are never stranded.
        plaintext = "legacy-secret"
        key = get_db_key()
        iv = os.urandom(16)
        legacy_value = prepare_for_save(iv, encrypt(key, iv, plaintext.encode("utf-8")))
        self.assertTrue(legacy_value.startswith("AES.1:"))
        self.assertEqual(plaintext, prepare_for_view(legacy_value))

    def test_decrypt_tampered_or_garbage_returns_empty(self):
        # A tampered AES.2 ciphertext (auth tag mismatch) and unparseable input
        # must degrade to "" rather than raising.
        encrypted = dojo_crypto_encrypt("tamper-me")
        scheme, nonce_hex, ct_hex = encrypted.split(":")
        ct = bytearray(binascii.a2b_hex(ct_hex))
        ct[0] ^= 0xFF  # flip a byte to break the GCM auth tag
        tampered = ":".join([scheme, nonce_hex, binascii.b2a_hex(bytes(ct)).decode("utf-8")])
        self.assertEqual("", prepare_for_view(tampered))
        self.assertEqual("", prepare_for_view("AES.2:zzzz:zzzz"))

    @patch("dojo.notifications.signals.Notifications")
    def test_create_default_notifications_without_template(self, mock_notifications):
        user = Dojo_User()
        user.id = 1

        save_mock_notifications = Mock(return_value=Notifications())
        mock_notifications.return_value = save_mock_notifications
        mock_notifications.DoesNotExist = Notifications.DoesNotExist
        mock_notifications.objects.get.side_effect = Notifications.DoesNotExist

        create_default_notifications(None, user, created=True)

        mock_notifications.assert_called_with(user=user)
        save_mock_notifications.save.assert_called_once()

    @patch("dojo.notifications.signals.Notifications")
    def test_create_default_notifications_with_template(self, mock_notifications):
        user = Dojo_User()
        user.id = 1

        template = Mock(Notifications(template=False, user=user))
        mock_notifications.objects.get.return_value = template

        create_default_notifications(None, user, created=True)

        mock_notifications.objects.get.assert_called_with(template=True)
        template.save.assert_called_once()

    # The ``default_group`` / ``default_group_role`` /
    # ``default_group_email_pattern`` knobs were relocated from
    # ``dojo.System_Settings`` onto ``pro.EnhancedSystemSettings``, and the
    # auto-assignment-to-default-group lifecycle that consumed them now
    # lives in ``pro.authorization.signals.user_post_save_default_group``.
    # OS-only deployments don't auto-assign new users to a group; the
    # equivalent Pro tests live in ``dojo-pro/unit_tests/authorization/``.


class assertNumOfModelsCreated:
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
            f"{created_count} {self.queryset.model} objects created, {self.num} expected. query: {self.queryset.query}, first 100 objects: {self.queryset.all().order_by('-id')[:100]}",
        )


@contextmanager
def assertTestImportModelsCreated(test_case, imports=0, reimports=0, affected_findings=0,
                                    created=0, closed=0, reactivated=0, untouched=0):

    with assertNumOfModelsCreated(test_case, TEST_IMPORTS, num=imports) as ti_import_count, \
            assertNumOfModelsCreated(test_case, TEST_REIMPORTS, num=reimports) as ti_reimport_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_AFFECTED, num=affected_findings) as tifa_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_CREATED, num=created) as tifa_created_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_CLOSED, num=closed) as tifa_closed_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_REACTIVATED, num=reactivated) as tifa_reactivated_count, \
            assertNumOfModelsCreated(test_case, TEST_IMPORT_FINDING_ACTION_UNTOUCHED, num=untouched) as tifa_untouched_count:

        yield (
                ti_import_count,
                ti_reimport_count,
                tifa_count,
                tifa_created_count,
                tifa_closed_count,
                tifa_reactivated_count,
                tifa_untouched_count,
              )


@contextmanager
def assertImportModelsCreated(test_case, tests=0, engagements=0, products=0, product_types=0, endpoints=0):

    locations_count = LOCATIONS if settings.V3_FEATURE_LOCATIONS else ENDPOINTS

    with assertNumOfModelsCreated(test_case, TESTS, num=tests) as test_count, \
            assertNumOfModelsCreated(test_case, ENGAGEMENTS, num=engagements) as engagement_count, \
            assertNumOfModelsCreated(test_case, PRODUCTS, num=products) as product_count, \
            assertNumOfModelsCreated(test_case, PRODUCT_TYPES, num=product_types) as product_type_count, \
            assertNumOfModelsCreated(test_case, locations_count, num=endpoints) as endpoint_count:

        yield (
                test_count,
                engagement_count,
                product_count,
                product_type_count,
                endpoint_count,
              )
