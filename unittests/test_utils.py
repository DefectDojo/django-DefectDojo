from dojo.models import IMPORT_CLOSED_FINDING, IMPORT_CREATED_FINDING, IMPORT_REACTIVATED_FINDING, IMPORT_UNTOUCHED_FINDING, \
    Engagement, Product, Test, Test_Import, Test_Import_Finding_Action, \
    Dojo_User, Dojo_Group, Dojo_Group_Member, Role, System_Settings, Notifications, \
    Product_Type, Endpoint
from contextlib import contextmanager
from .dojo_test_case import DojoTestCase
from unittest.mock import patch, Mock
from dojo.utils import dojo_crypto_encrypt, prepare_for_view, user_post_save
from dojo.authorization.roles_permissions import Roles
import logging


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


class TestUtils(DojoTestCase):
    def test_encryption(self):
        test_input = "Hello World!"
        encrypt = dojo_crypto_encrypt(test_input)
        test_output = prepare_for_view(encrypt)
        self.assertEqual(test_input, test_output)

    @patch('dojo.models.System_Settings.objects')
    @patch('dojo.utils.Dojo_Group_Member')
    @patch('dojo.utils.Notifications')
    def test_user_post_save_without_template(self, mock_notifications, mock_member, mock_settings):
        user = Dojo_User()
        user.id = 1

        group = Dojo_Group()
        group.id = 1

        role = Role.objects.get(id=Roles.Reader)

        system_settings_group = System_Settings()
        system_settings_group.default_group = group
        system_settings_group.default_group_role = role

        mock_settings.get.return_value = system_settings_group
        save_mock_member = Mock(return_value=Dojo_Group_Member())
        mock_member.return_value = save_mock_member

        save_mock_notifications = Mock(return_value=Notifications())
        mock_notifications.return_value = save_mock_notifications
        mock_notifications.objects.get.side_effect = Exception("Mock no templates")

        user_post_save(None, user, True)

        mock_member.assert_called_with(group=group, user=user, role=role)
        save_mock_member.save.assert_called_once()

        mock_notifications.assert_called_with(user=user)
        save_mock_notifications.save.assert_called_once()

    @patch('dojo.models.System_Settings.objects')
    @patch('dojo.utils.Dojo_Group_Member')
    @patch('dojo.utils.Notifications')
    def test_user_post_save_with_template(self, mock_notifications, mock_member, mock_settings):
        user = Dojo_User()
        user.id = 1

        group = Dojo_Group()
        group.id = 1

        template = Mock(Notifications(template=False, user=user))

        role = Role.objects.get(id=Roles.Reader)

        system_settings_group = System_Settings()
        system_settings_group.default_group = group
        system_settings_group.default_group_role = role

        mock_settings.get.return_value = system_settings_group
        save_mock_member = Mock(return_value=Dojo_Group_Member())
        mock_member.return_value = save_mock_member

        mock_notifications.objects.get.return_value = template

        user_post_save(None, user, True)

        mock_member.assert_called_with(group=group, user=user, role=role)
        save_mock_member.save.assert_called_once()

        mock_notifications.objects.get.assert_called_with(template=True)
        template.save.assert_called_once()

    @patch('dojo.models.System_Settings.objects')
    @patch('dojo.utils.Dojo_Group_Member')
    @patch('dojo.utils.Notifications')
    def test_user_post_save_email_pattern_matches(self, mock_notifications, mock_member, mock_settings):
        user = Dojo_User()
        user.id = 1
        user.email = 'john.doe@example.com'

        group = Dojo_Group()
        group.id = 1

        role = Role.objects.get(id=Roles.Reader)

        system_settings_group = System_Settings()
        system_settings_group.default_group = group
        system_settings_group.default_group_role = role
        system_settings_group.default_group_email_pattern = '.*@example.com'

        mock_settings.get.return_value = system_settings_group
        save_mock_member = Mock(return_value=Dojo_Group_Member())
        mock_member.return_value = save_mock_member
        save_mock_notifications = Mock(return_value=Notifications())
        mock_notifications.return_value = save_mock_notifications
        mock_notifications.objects.get.side_effect = Exception("Mock no templates")

        user_post_save(None, user, True)

        mock_member.assert_called_with(group=group, user=user, role=role)
        save_mock_member.save.assert_called_once()

    @patch('dojo.models.System_Settings.objects')
    @patch('dojo.utils.Dojo_Group_Member')
    @patch('dojo.utils.Notifications')
    def test_user_post_save_email_pattern_does_not_match(self, mock_notifications, mock_member, mock_settings):
        user = Dojo_User()
        user.id = 1
        user.email = 'john.doe@partner.example.com'

        group = Dojo_Group()
        group.id = 1

        role = Role.objects.get(id=Roles.Reader)

        system_settings_group = System_Settings()
        system_settings_group.default_group = group
        system_settings_group.default_group_role = role
        system_settings_group.default_group_email_pattern = '.*@example.com'
        save_mock_notifications = Mock(return_value=Notifications())
        mock_notifications.return_value = save_mock_notifications
        mock_notifications.objects.get.side_effect = Exception("Mock no templates")

        mock_settings.get.return_value = system_settings_group
        save_mock_member = Mock(return_value=Dojo_Group_Member())
        mock_member.return_value = save_mock_member

        user_post_save(None, user, True)

        mock_member.assert_not_called()
        save_mock_member.save.assert_not_called()


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
            "%i %s objects created, %i expected. query: %s, first 100 objects: %s" % (
                created_count, self.queryset.model, self.num, self.queryset.query, self.queryset.all().order_by('-id')[:100]
            )
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
                tifa_untouched_count
              )


@contextmanager
def assertImportModelsCreated(test_case, tests=0, engagements=0, products=0, product_types=0, endpoints=0):

    with assertNumOfModelsCreated(test_case, TESTS, num=tests) as test_count, \
            assertNumOfModelsCreated(test_case, ENGAGEMENTS, num=engagements) as engagement_count, \
            assertNumOfModelsCreated(test_case, PRODUCTS, num=products) as product_count, \
            assertNumOfModelsCreated(test_case, PRODUCT_TYPES, num=product_types) as product_type_count, \
            assertNumOfModelsCreated(test_case, ENDPOINTS, num=endpoints) as endpoint_count:

        yield (
                test_count,
                engagement_count,
                product_count,
                product_type_count,
                endpoint_count,
              )
