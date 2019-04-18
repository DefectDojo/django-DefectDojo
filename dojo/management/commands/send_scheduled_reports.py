import re

from django.core.management.base import BaseCommand

from dojo.reports.widgets import report_widget_factory
from dojo.models import Report_Interval, Engagement
from datetime import datetime, time, timedelta
from django.template.loader import render_to_string
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from dateutil import parser


class Command(BaseCommand):
    help = "Details:\n\tChecks if any reports are due to be sent and if so, sends them out"

    def add_arguments(self, parser):
        parser.add_argument('-s', '--simulate', type=str, help='Provide a time that will be simulated as current time', )

    def handle(self, *args, **options):
        simulate = options['simulate'] or None
        if simulate is not None:
            simulate = parser.parse(simulate, fuzzy=True)

        interval_list = Report_Interval.objects.all()

        # Build reference dataset for faster lookup
        current_time = timezone.localtime()
        start_day = timezone.make_aware(datetime.combine(current_time.date(), time()), timezone=current_time.tzinfo)
        start_week = start_day - timedelta(days=start_day.weekday())
        start_month = start_day.replace(day=1)
        start_year = start_day.replace(month=1, day=1)

        event_date_reference = {
            1: start_day,
            2: start_week,
            3: start_month,
            4: start_year,
        }
        event_date_reference_keys = event_date_reference.keys()

        event_object_reference = {
            5: {
                'Object': Engagement,
                'DateField': 'target_start',
                'Filter': {
                    'active': True
                }
            }
        }
        event_object_reference_keys = event_object_reference.keys()

        placeholder_regex = re.compile('{([\w._]+?)}')

        # Allows to use a dynamic placeholder like {product.prod_manager}
        def resolve_recipient_placeholder(obj, placeholder):
            if "." in placeholder:
                components = placeholder.split(".")

                for component in components:
                    obj = getattr(obj, component, None)
            else:
                obj = getattr(obj, placeholder, None)

            return obj

        # Compile and send the actual report
        def send_report(interval, related_object=None):
            report = interval.report
            host = report.host

            selected_widgets = report_widget_factory(json_data=report.options, user=report.requester, host=host,
                                                 finding_notes=False, finding_images=False)
            options = selected_widgets['report-options']
            finding_notes = (options.include_finding_notes == '1')
            finding_images = (options.include_finding_images == '1')

            selected_widgets = report_widget_factory(json_data=report.options, user=report.requester, host=host,
                                                 finding_notes=finding_notes, finding_images=finding_images)

            widgets = selected_widgets.values()
            send_body = render_to_string('dojo/custom_asciidoc_report.html',
                          {"widgets": widgets,
                           "host": host,
                           "finding_notes": finding_notes,
                           "finding_images": finding_images,
                           "user_id": report.requester,
                           "override_base": "blank.html"})

            recipients = interval.recipients.splitlines()
            for i in range(len(recipients)):
                check_placeholder = placeholder_regex.match(recipients[i])
                insert_placeholder = None
                if check_placeholder is not None:
                    if related_object is not None:
                        extractedPlaceholder = check_placeholder.group(1)
                        lookup_placeholder = resolve_recipient_placeholder(related_object, extractedPlaceholder)

                        if lookup_placeholder is not None and extractedPlaceholder is not None:
                            try:
                                validate_email(lookup_placeholder)
                                insert_placeholder = lookup_placeholder
                            except ValidationError:
                                self.stdout.write('Placeholder "' + extractedPlaceholder + '" resolved to "' + lookup_placeholder + '" for "' + str(related_object) + '", which is not a valid email address')
                    else:
                        self.stdout.write('Placeholder "' + extractedPlaceholder + '" was used, but the event is not connected to an object')
                else:
                    continue

                recipients[i] = insert_placeholder

            recipients = [recipient for recipient in recipients if recipient is not None]
            if len(recipients) > 0:
                success_mail = send_mail(interval.report.name,
                          send_body,
                          settings.PORT_SCAN_RESULT_EMAIL_FROM,
                          recipients,
                          fail_silently=False,
                          html_message=send_body)

                interval.last_run = timezone.now()
                interval.save()

                return success_mail
            else:
                return None

        # Loop through set up intervals
        sent_reports = 0
        for interval in interval_list:
            if simulate is not None:
                compare_time = simulate
            elif interval.time_count > 0:
                time_offset = timedelta(seconds=interval.time_count * interval.time_unit)
                compare_time = current_time + time_offset
            else:
                compare_time = current_time

            if interval.event in event_date_reference_keys:
                # If the event is a static date, we can calculate it easily
                if compare_time == event_date_reference[interval.event]:
                    sent_reports += 1
                    send_report(interval)
            elif interval.event in event_object_reference_keys:
                # The event is related to the date field of an object
                object_reference = event_object_reference[interval.event]

                object_reference['Filter'][object_reference['DateField']] = compare_time
                check_objects = (object_reference['Object']).objects.filter(**object_reference['Filter'])
                for check_object in check_objects:
                    sent_reports += 1
                    send_report(interval, check_object)
        
        self.stdout.write("Reports sent out: " + str(sent_reports))
