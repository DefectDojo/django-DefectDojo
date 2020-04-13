# #  product
import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render

from dojo.models import Notifications, Dojo_User
from dojo.utils import add_breadcrumb
from dojo.forms import NotificationsForm
from django.db.models import Q, Prefetch, Count

logger = logging.getLogger(__name__)


def personal_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(user=request.user)
    except:
        notifications_obj = Notifications(user=request.user)

    form = NotificationsForm(instance=notifications_obj)
    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            new_settings = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Settings saved.',
                                 extra_tags='alert-success')

    add_breadcrumb(title="Personal notification settings", top_level=False, request=request)

    event = 'scan_added'
    # personal_product_notifications = request.user.notifications_set.filter(Q(product_id=121) | Q(product__isnull=True)).exclude(Q(**{"%s__exact" % event: ''}))

    # not_users = Dojo_User.objects.filter(is_active=True).filter(Q(notifications__product_id=121) | Q(notifications__product__isnull=True))

    not_users = Dojo_User.objects.filter(is_active=True).prefetch_related(Prefetch(
        "notifications_set",
        queryset=Notifications.objects.filter(Q(product_id=121) | Q(product__isnull=True)),
        to_attr="applicable_notifications"
    )).annotate(applicable_notifications_count=Count('notifications__id', filter=Q(notifications__product_id=121) | Q(notifications__product__isnull=True))).filter(applicable_notifications_count__gt=0)

    for u in not_users:
        u.merged_notifications = Notifications.merge_notification_list(u.applicable_notifications)

    return render(request, 'dojo/notifications.html',
                  {'form': form,
                   'scope': 'personal',
                   'admin': request.user.is_superuser,
                   'not_users': not_users,
                #    'personal_product_notifications': personal_product_notifications
                   })


@user_passes_test(lambda u: u.is_superuser)
def system_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(user=None)
    except:
        notifications_obj = Notifications(user=None)

    form = NotificationsForm(instance=notifications_obj)
    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            new_settings = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Settings saved.',
                                 extra_tags='alert-success')

    add_breadcrumb(title="System notification settings", top_level=False, request=request)
    return render(request, 'dojo/notifications.html',
                  {'form': form,
                   'scope': 'system',
                   'admin': request.user.is_superuser})
