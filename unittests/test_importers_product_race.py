import logging
from unittest import mock

from parameterized import parameterized

from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.models import Product, Product_Type

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)

PRODUCT_NAME = "TestImportersProductRace"
REQUESTED_TYPE = "Product Race Requested"


class TestImportersProductRace(DojoTestCase):

    """
    Regression: two concurrent auto-creating imports of the same product name could fail one
    of them with a 500 instead of returning the product the other one had just created.

    `get_or_create_product()` guards with `get_target_product_if_exists()`, which matches on
    `name` alone, so the `get_or_create()` below it is reached only when the name looked free.
    That call passed `prod_type` and `description` as *lookup* kwargs rather than `defaults=`,
    which made its `get` half match on all three columns -- so a row another request committed
    inside the guard's window was invisible to it. Django fell through to `create`, lost to the
    `dojo_product_name_key` unique index, and its recovery `get` reused the same three-column
    lookup, missing the winner's row a second time, so the IntegrityError was re-raised:

        duplicate key value violates unique constraint "dojo_product_name_key"
        DETAIL: Key (name)=(TestImportersProductRace) already exists.

    `name` is the only unique column, so `name` is the only lookup; the rest are `defaults=`.
    The race window itself is unchanged -- the loser now resolves to the winner's product
    instead of raising, and does not overwrite it.
    """

    def setUp(self):
        super().setUp()
        self.requested_type, _ = Product_Type.objects.get_or_create(name=REQUESTED_TYPE)
        self.auto_create_manager = AutoCreateContextManager()

    def _auto_create_through_the_race_window(self):
        """
        Call the creator as a request that lost the race would reach it.

        The losing request ran `get_target_product_if_exists()` before the winner committed,
        so it saw nothing and fell through to the create. Patching that guard to None
        reproduces exactly that state, and is the only way to reach the `get_or_create()` at
        all: left alone the guard returns the existing product first, which is why this bug
        stayed latent.
        """
        with mock.patch.object(AutoCreateContextManager, "get_target_product_if_exists", return_value=None):
            return self.auto_create_manager.get_or_create_product(
                product_name=PRODUCT_NAME,
                product_type_name=REQUESTED_TYPE,
                auto_create_context=True,
            )

    @parameterized.expand([
        # The winner filed the name under a different organization.
        ("competing_organization", "Product Race Competitor", PRODUCT_NAME),
        # The winner came from a path that writes its own description (a connector sync, or a
        # person creating the asset in the UI inside the window).
        ("competing_description", REQUESTED_TYPE, "Created by another importer"),
        # Control: the winner wrote exactly what this request would have. Already worked.
        ("identical_row", REQUESTED_TYPE, PRODUCT_NAME),
    ])
    def test_losing_the_create_race_returns_the_winners_product(
        self, case_name, winner_type_name, winner_description,
    ):
        winner_type, _ = Product_Type.objects.get_or_create(name=winner_type_name)
        winner = Product.objects.create(
            name=PRODUCT_NAME,
            prod_type=winner_type,
            description=winner_description,
        )

        product = self._auto_create_through_the_race_window()

        self.assertEqual(
            winner.pk, product.pk,
            msg=f"expected the winner's product pk={winner.pk}, got pk={product.pk}",
        )
        self.assertEqual(
            1, Product.objects.filter(name=PRODUCT_NAME).count(),
            msg="the losing request must not add a second product under the same name",
        )
        persisted = Product.objects.get(pk=winner.pk)
        self.assertEqual(
            winner_description, persisted.description,
            msg=f"defaults must not overwrite the winner: expected description="
                f"{winner_description!r}, persisted={persisted.description!r}",
        )
        self.assertEqual(
            winner_type_name, persisted.prod_type.name,
            msg=f"defaults must not overwrite the winner: expected prod_type={winner_type_name!r}, "
                f"persisted={persisted.prod_type.name!r}",
        )

    def test_auto_create_still_populates_a_product_when_nothing_races(self):
        """Control: with no competing row the defaults still land on the created product."""
        self.assertFalse(Product.objects.filter(name=PRODUCT_NAME).exists())

        product = self._auto_create_through_the_race_window()

        persisted = Product.objects.get(pk=product.pk)
        self.assertEqual(
            PRODUCT_NAME, persisted.description,
            msg=f"expected description={PRODUCT_NAME!r}, persisted={persisted.description!r}",
        )
        self.assertEqual(
            REQUESTED_TYPE, persisted.prod_type.name,
            msg=f"expected prod_type={REQUESTED_TYPE!r}, persisted={persisted.prod_type.name!r}",
        )
