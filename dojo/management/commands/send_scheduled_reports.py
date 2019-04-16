import sys
import re

from django.core.management import call_command
from django.core.management.base import BaseCommand
from dojo.utils import create_notification

from dojo.reports.widgets import CoverPage, PageBreak, TableOfContents, WYSIWYGContent, FindingList, EndpointList, \
    CustomReportJsonForm, ReportOptions, report_widget_factory
from dojo.models import Report_Interval, Engagement, Report
from datetime import datetime, date, time, timedelta
from django.core.mail import send_mail
from django.conf import settings


from pprint import pprint
class Command(BaseCommand):
    help = "Details:\n\tChecks if any reports are due to be sent and if so, sends them out"

    def handle(self, *args, **options):
        interval_list = Report_Interval.objects.all()
        
        # Build reference dataset for faster lookup
        current_time = datetime.now()
        start_day = datetime.combine(date.today(), time())
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
        
        placeholder_regex = re.compile('{[\w._]+?}')
        
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
        def send_report(interval, related_object = None):
            report = interval.report
            finding_notes = (report.options.include_finding_notes == '1')
            finding_images = (report.options.include_finding_images == '1')
            host = report.host
            
            selected_widgets = report_widget_factory(json_data=report.options, user=report.requester, host=host,
                                                 finding_notes=finding_notes, finding_images=finding_images)
            widgets = selected_widgets.values()
            send_body = render(request,
                          'dojo/custom_asciidoc_report.html',
                          {"widgets": widgets,
                           "host": host,
                           "finding_notes": finding_notes,
                           "finding_images": finding_images,
                           "user_id": report.requester})
            
            recipients = interval.recipients.splitlines()
            for i in range(len(recipients)):
                check_placeholder = placeholder_regex.match(recipients[i])
                insert_placeholder = None
                if check_placeholder:
                    insert_placeholder = resolve_recipient_placeholder(related_object, check_placeholder.group(1))
                else:
                    continue
                
                if insert_placeholder == None:
                    # If it didn't work, we will overwrite it with an email that gives users more hints about what failed
                    # Console could work, but researching that takes longer
                    insert_placeholder = 'placeholder-resolve-failed@' + str(check_placeholder.group(1))
                
                recipients[i] = insert_placeholder
            
            return send_mail(interval.name,
                      send_body,
                      settings.PORT_SCAN_RESULT_EMAIL_FROM,
                      recipients,
                      fail_silently=False)

        # Loop through set up intervals
        for interval in interval_list:
            if interval.time_count > 0:
                time_offset = timedelta(seconds=interval.time_count * interval.time_unit)
                compare_time = current_time + time_offset
            else:
                time_offset = 0
                compare_time = current_time

            if interval.event in event_date_reference_keys:
                # If the event is a static date, we can calculate it easily
                if compare_time == event_date_reference[interval.event]:
                    send_report(interval)
            elif interval.event in event_object_reference_keys:
                # The event is related to the date field of an object
                object_reference = event_object_reference[interval.event]
                
                object_reference['Filter'][object_reference['DateField']] = compare_time
                check_objects = (object_reference['Object']).objects.filter(**timeFilter).filter(**object_reference['Filter'])
                for check_object in check_objects:
                    send_report(interval, check_object)
