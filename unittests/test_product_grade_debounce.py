"""
Product grade recalculation is debounced per product.

Regression: every finding save during an import or rules run scheduled its own ``calculate_grade``
task, so a bulk operation queued one task per finding (over a thousand in a few minutes on one
instance) for a value that only needs computing once per product per burst; the flood saturated the
worker pool and, with several grade tasks in flight at once, pushed the pod past its memory limit.
Grade requests now coalesce: the first change in a window enqueues one task with a countdown, later
changes in that window are no-ops, and the task clears the guard as it starts so changes that land
mid-run re-arm a follow-up recalculation.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings

from dojo.utils import calculate_grade, grade_debounce_cache_key, schedule_product_grade

from .dojo_test_case import DojoTestCase


@override_settings(PRODUCT_GRADE_DEBOUNCE_SECONDS=30)
class TestProductGradeDebounce(DojoTestCase):
    # No fixture: the guard is keyed by product id alone, and calculate_grade drops it before it looks
    # the product up, so the ids below do not need to exist.

    def setUp(self):
        super().setUp()
        for product_id in (1, 2):
            cache.delete(grade_debounce_cache_key(product_id))

    def test_a_burst_enqueues_one_delayed_task(self):
        with patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch:
            for _ in range(5):
                schedule_product_grade(1)
        dispatch.assert_called_once()
        args, kwargs = dispatch.call_args
        self.assertIs(args[0], calculate_grade)
        self.assertEqual(args[1], 1)
        self.assertGreater(kwargs["countdown"], 0)

    @override_settings(PRODUCT_GRADE_DEBOUNCE_SECONDS=45)
    def test_the_countdown_follows_the_setting(self):
        with patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch:
            schedule_product_grade(1)
        self.assertEqual(dispatch.call_args.kwargs["countdown"], 45)

    def test_force_sync_bypasses_the_debounce(self):
        with patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch:
            schedule_product_grade(1, force_sync=True)
            schedule_product_grade(1, force_sync=True)
        self.assertEqual(dispatch.call_count, 2)
        for call in dispatch.call_args_list:
            self.assertTrue(call.kwargs.get("force_sync"))
            self.assertNotIn("countdown", call.kwargs)

    def test_the_task_clears_the_guard_so_later_changes_re_arm(self):
        with patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch:
            schedule_product_grade(1)
            with patch("dojo.utils.calculate_grade_internal"):
                calculate_grade(1)
            schedule_product_grade(1)
        self.assertEqual(dispatch.call_count, 2)

    def test_products_do_not_share_a_guard(self):
        with patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch:
            schedule_product_grade(1)
            schedule_product_grade(2)
        self.assertEqual(dispatch.call_count, 2)

    def test_a_blocking_user_recalculates_in_the_foreground_every_time(self):
        # A profile that blocks background execution expects the grade when the call returns, and a
        # foreground run has no queue to flood, so it is never held back by a pending marker.
        with (
            patch("dojo.decorators.we_want_async", return_value=False),
            patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch,
        ):
            schedule_product_grade(1)
            schedule_product_grade(1)
        self.assertEqual(dispatch.call_count, 2)
        for call in dispatch.call_args_list:
            self.assertNotIn("countdown", call.kwargs)
