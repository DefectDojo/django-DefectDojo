import requests
import logging
from django.core.mail import EmailMessage
from dojo.models import Notifications, Dojo_User, Alerts, UserContactInfo
from django.template.loader import render_to_string
from django.db.models import Q, Count, Prefetch
from django.urls import reverse

logger = logging.getLogger(__name__)


def create_notification(event=None, *args, **kwargs):
    # System notifications
    try:
        system_notifications = Notifications.objects.get(user=None)
    except Exception:
        system_notifications = Notifications()

    logger.debug('creating system notifications')
    process_notifications(event, system_notifications, *args, **kwargs)

    if 'recipients' in kwargs:
        # mimic existing code so that when recipients is specified, no other personal notifications are sent.
        logger.debug('creating notifications for recipients')
        for recipient_notifications in Notifications.objects.filter(user__username__in=kwargs['recipients'], user__is_active=True):
            # kwargs.update({'user': recipient_notifications.user})
            process_notifications(event, recipient_notifications, *args, **kwargs)
    else:
        # Personal but global notifications
        # only retrieve users which have at least one notification type enabled for this event type.
        logger.debug('creating personal notifications')

        product = None
        if 'product' in kwargs:
            product = kwargs.get('product')

        if not product and 'engagement' in kwargs:
            product = kwargs['engagement'].product

        if not product and 'test' in kwargs:
            product = kwargs['test'].engagement.product

        # get users with either global notifications, or a product specific noditiciation
        users = Dojo_User.objects.filter(is_active=True).prefetch_related(Prefetch(
            "notifications_set",
            queryset=Notifications.objects.filter(Q(product_id=product) | Q(product__isnull=True)),
            to_attr="applicable_notifications"
        )).annotate(applicable_notifications_count=Count('notifications__id', filter=Q(notifications__product_id=product) | Q(notifications__product__isnull=True))).filter(applicable_notifications_count__gt=0)

        for user in users:
            # send notifications to user after merging possible multiple notifications records (i.e. personal global + personal product)
            # kwargs.update({'user': user})
            process_notifications(event, Notifications.merge_notifications_list(user.applicable_notifications), *args, **kwargs)


def create_description(event, *args, **kwargs):
    if "description" not in kwargs.keys():
        if event == 'product_added':
            kwargs["description"] = "Product " + kwargs['title'] + " has been created successfully."
        else:
            kwargs["description"] = "Event " + str(event) + " has occured."

    return kwargs["description"]


def create_notification_message(event, user, notification_type, *args, **kwargs):
    template = 'notifications/%s.tpl' % event.replace('/', '')
    kwargs.update({'type': notification_type})
    kwargs.update({'user': user})

    try:
        notification = render_to_string(template, kwargs)
    except Exception as e:
        logger.exception(e)
        create_description(event)
        notification = render_to_string('notifications/other.tpl', kwargs)

    return notification


def process_notifications(event, notifications=None, *args, **kwargs):
    from dojo.utils import get_system_setting

    if not notifications:
        logger.warn('no notifications!')
        return

    sync = 'initiator' in kwargs and hasattr(kwargs['initiator'], 'usercontactinfo') and kwargs['initiator'].usercontactinfo.block_execution

    logger.debug('sync: %s', sync)
    logger.debug('sending notifications ' + ('synchronously' if sync else 'asynchronously'))
    logger.debug(vars(notifications))

    slack_enabled = get_system_setting('enable_slack_notifications')
    hipchat_enabled = get_system_setting('enable_hipchat_notifications')
    mail_enabled = get_system_setting('enable_mail_notifications')

    from dojo.tasks import send_slack_notification_task, send_alert_notification_task, send_hipchat_notification_task, send_mail_notification_task

    if slack_enabled and 'slack' in getattr(notifications, event):
        if not sync:
            send_slack_notification_task.delay(event, notifications.user, *args, **kwargs)
        else:
            send_slack_notification(event, notifications.user, *args, **kwargs)

    if hipchat_enabled and 'hipchat' in getattr(notifications, event):
        if not sync:
            send_hipchat_notification_task.delay(event, notifications.user, *args, **kwargs)
        else:
            send_hipchat_notification(event, notifications.user, *args, **kwargs)

    if mail_enabled and 'mail' in getattr(notifications, event):
        if not sync:
            send_mail_notification_task.delay(event, notifications.user, *args, **kwargs)
        else:
            send_mail_notification(event, notifications.user, *args, **kwargs)

    print(getattr(notifications, event, None))
    if 'alert' in getattr(notifications, event, None):
        if not sync:
            send_alert_notification_task.delay(event, notifications.user, *args, **kwargs)
        else:
            send_alert_notification(event, notifications.user, *args, **kwargs)


def send_slack_notification(event, user=None, *args, **kwargs):
    from dojo.utils import get_system_setting, get_slack_user_id
    if user is not None:
        if hasattr(user, 'usercontactinfo') and user.usercontactinfo.slack_username is not None:
            slack_user_id = user.usercontactinfo.slack_user_id
            if user.usercontactinfo.slack_user_id is None:
                # Lookup the slack userid
                slack_user_id = get_slack_user_id(
                    user.usercontactinfo.slack_username)
                slack_user_save = UserContactInfo.objects.get(user_id=user.id)
                slack_user_save.slack_user_id = slack_user_id
                slack_user_save.save()

            channel = '@%s' % slack_user_id
        else:
            # user has no slack username, skip
            return
    else:
        channel = get_system_setting('slack_channel')

    try:
        res = requests.request(
            method='POST',
            url='https://slack.com/api/chat.postMessage',
            data={
                'token': get_system_setting('slack_token'),
                'channel': channel,
                'username': get_system_setting('slack_username'),
                'text': create_notification_message(event, user, 'slack', *args, **kwargs)
            })
    except Exception as e:
        logger.exception(e)
        log_alert(e, *args, **kwargs)
        pass


def send_hipchat_notification(event, user=None, *args, **kwargs):
    from dojo.utils import get_system_setting
    if user:
        # HipChat doesn't seem to offer direct message functionality, so no HipChat PM functionality here...
        return

    try:
        # We use same template for HipChat as for slack
        res = requests.request(
            method='POST',
            url='https://%s/v2/room/%s/notification?auth_token=%s' %
            (get_system_setting('hipchat_site'),
            get_system_setting('hipchat_channel'),
            get_system_setting('hipchat_token')),
            data={
                'message': create_notification_message(event, 'slack', *args, **kwargs),
                'message_format': 'text'
            })
    except Exception as e:
        logger.exception(e)
        log_alert(e, *args, **kwargs)
        pass


def send_mail_notification(event, user=None, *args, **kwargs):
    from dojo.utils import get_system_setting

    if user:
        address = user.email
    else:
        address = get_system_setting('mail_notifications_to')

    subject = '%s notification' % get_system_setting('team_name')
    if 'title' in kwargs:
        subject += ': %s' % kwargs['title']
    try:
        email = EmailMessage(
            subject,
            create_notification_message(event, user, 'mail', *args, **kwargs),
            get_system_setting('mail_notifications_from'),
            [address],
            headers={"From": "{}".format(get_system_setting('mail_notifications_from'))}
        )
        email.content_subtype = 'html'
        logger.debug('sending email alert')
        # logger.info(create_notification_message(event, 'mail'))
        email.send(fail_silently=False)

    except Exception as e:
        logger.exception(e)
        log_alert(e, *args, **kwargs)
        pass


def send_alert_notification(event, user=None, *args, **kwargs):
    icon = kwargs.get('icon', 'info-circle')
    alert = Alerts(
        user_id=user,
        title=kwargs.get('title'),
        description=create_notification_message(event, user, 'alert', *args, **kwargs),
        url=kwargs.get('url', reverse('alerts')),
        icon=icon,
        source=Notifications._meta.get_field(event).verbose_name.title())
    alert.save()


def log_alert(e, *args, **kwargs):
    users = Dojo_User.objects.filter(is_superuser=True)
    for user in users:
        alert = Alerts(
            user_id=user,
            url=kwargs.get('url', reverse('alerts')),
            title='Notification issue',
            description="%s" % e,
            icon="exclamation-triangle",
            source="Notifications")
        alert.save()
