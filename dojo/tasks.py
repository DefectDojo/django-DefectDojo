import tempfile
from datetime import timedelta
from django.db.models import Count
from django.conf import settings
from django.core.files.base import ContentFile
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils.http import urlencode
from dojo.celery import app
from celery.utils.log import get_task_logger
from celery.decorators import task
from dojo.models import Product, Finding, Engagement, System_Settings
from django.utils import timezone
from dojo.signals import dedupe_signal

import pdfkit
from dojo.tools.tool_issue_updater import tool_issue_updater, update_findings_from_source_issues
from dojo.utils import sync_false_history, calculate_grade
from dojo.reports.widgets import report_widget_factory
from dojo.utils import add_comment, add_epic, add_jira_issue, update_epic, \
                       close_epic, sync_rules, \
                       update_external_issue, add_external_issue, \
                       close_external_issue, reopen_external_issue, sla_compute_and_notify
from dojo.notifications.helper import create_notification
import logging

fmt = getattr(settings, 'LOG_FORMAT', None)
lvl = getattr(settings, 'LOG_LEVEL', logging.DEBUG)
logging.basicConfig(format=fmt, level=lvl)

logger = get_task_logger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


# Logs the error to the alerts table, which appears in the notification toolbar
def log_generic_alert(source, title, description):
    create_notification(event='other', title=title, description=description,
                        icon='bullseye', source=source)


@app.task(bind=True)
def add_alerts(self, runinterval):
    now = timezone.now()

    upcoming_engagements = Engagement.objects.filter(target_start__gt=now + timedelta(days=3), target_start__lt=now + timedelta(days=3) + runinterval).order_by('target_start')
    for engagement in upcoming_engagements:
        create_notification(event='upcoming_engagement',
                            title='Upcoming engagement: %s' % engagement.name,
                            engagement=engagement,
                            recipients=[engagement.lead],
                            url=reverse('view_engagement', args=(engagement.id,)))

    stale_engagements = Engagement.objects.filter(
        target_start__gt=now - runinterval,
        target_end__lt=now,
        status='In Progress').order_by('-target_end')
    for eng in stale_engagements:
        create_notification(event='stale_engagement',
                            title='Stale Engagement: %s' % eng.name,
                            description='The engagement "%s" is stale. Target end was %s.' % (eng.name, eng.target_end.strftime("%b. %d, %Y")),
                            url=reverse('view_engagement', args=(eng.id,)),
                            recipients=[eng.lead])

    system_settings = System_Settings.objects.get()
    if system_settings.engagement_auto_close:
        # Close Engagements older than user defined days
        close_days = system_settings.engagement_auto_close_days
        unclosed_engagements = Engagement.objects.filter(target_end__lte=now - timedelta(days=close_days),
                                                        status='In Progress').order_by('target_end')

        for eng in unclosed_engagements:
            create_notification(event='auto_close_engagement',
                                title=eng.name,
                                description='The engagement "%s" has auto-closed. Target end was %s.' % (eng.name, eng.target_end.strftime("%b. %d, %Y")),
                                url=reverse('view_engagement', args=(eng.id,)),
                                recipients=[eng.lead])

        unclosed_engagements.update(status="Completed", active=False, updated=timezone.now())

    # Calculate grade
    if system_settings.enable_product_grade:
        products = Product.objects.all()
        for product in products:
            calculate_grade(product)


@app.task(bind=True)
def async_pdf_report(self,
                     report=None,
                     template="None",
                     filename='report.pdf',
                     report_title=None,
                     report_subtitle=None,
                     report_info=None,
                     context={},
                     uri=None):
    xsl_style_sheet = settings.DOJO_ROOT + "/static/dojo/xsl/pdf_toc.xsl"
    x = urlencode({'title': report_title,
                   'subtitle': report_subtitle,
                   'info': report_info})

    cover = context['host'] + reverse(
        'report_cover_page') + "?" + x

    try:
        config = pdfkit.configuration(wkhtmltopdf=settings.WKHTMLTOPDF_PATH)
        report.task_id = async_pdf_report.request.id
        report.save()
        bytes = render_to_string(template, context)
        itoc = context['include_table_of_contents']
        if itoc:
            toc = {'xsl-style-sheet': xsl_style_sheet}
        else:
            toc = None
        pdf = pdfkit.from_string(bytes,
                                 False,
                                 configuration=config,
                                 cover=cover,
                                 toc=toc)
        if report.file.name:
            with open(report.file.path, 'w') as f:
                f.write(pdf)
            f.close()
        else:
            f = ContentFile(pdf)
            report.file.save(filename, f)
        report.status = 'success'
        report.done_datetime = timezone.now()
        report.save()

        create_notification(event='report_created', title='Report created', description='The report "%s" is ready.' % report.name, url=uri, report=report, objowner=report.requester)
    except Exception as e:
        report.status = 'error'
        report.save()
        log_generic_alert("PDF Report", "Report Creation Failure", "Make sure WKHTMLTOPDF is installed. " + str(e))
    return True


@app.task(bind=True)
def async_custom_pdf_report(self,
                            report=None,
                            template="None",
                            filename='report.pdf',
                            host=None,
                            user=None,
                            uri=None,
                            finding_notes=False,
                            finding_images=False):
    config = pdfkit.configuration(wkhtmltopdf=settings.WKHTMLTOPDF_PATH)

    selected_widgets = report_widget_factory(json_data=report.options, request=None, user=user,
                                             finding_notes=finding_notes, finding_images=finding_images, host=host)

    widgets = list(selected_widgets.values())
    temp = None

    try:
        report.task_id = async_custom_pdf_report.request.id
        report.save()

        toc = None
        toc_depth = 4

        if 'table-of-contents' in selected_widgets:
            xsl_style_sheet_tempalte = "dojo/pdf_toc.xsl"
            temp = tempfile.NamedTemporaryFile()

            toc_settings = selected_widgets['table-of-contents']

            toc_depth = toc_settings.depth
            toc_bytes = render_to_string(xsl_style_sheet_tempalte, {'widgets': widgets,
                                                                    'depth': toc_depth,
                                                                    'title': toc_settings.title})
            temp.write(toc_bytes)
            temp.seek(0)

            toc = {'toc-header-text': toc_settings.title,
                   'xsl-style-sheet': temp.name}

        # default the cover to not come first by default
        cover_first_val = False

        cover = None
        if 'cover-page' in selected_widgets:
            cover_first_val = True
            cp = selected_widgets['cover-page']
            x = urlencode({'title': cp.title,
                           'subtitle': cp.sub_heading,
                           'info': cp.meta_info})
            cover = host + reverse(
                'report_cover_page') + "?" + x
        bytes = render_to_string(template, {'widgets': widgets,
                                            'toc_depth': toc_depth,
                                            'host': host,
                                            'report_name': report.name})
        pdf = pdfkit.from_string(bytes,
                                 False,
                                 configuration=config,
                                 toc=toc,
                                 cover=cover,
                                 cover_first=cover_first_val)

        if report.file.name:
            with open(report.file.path, 'w') as f:
                f.write(pdf)
            f.close()
        else:
            f = ContentFile(pdf)
            report.file.save(filename, f)
        report.status = 'success'
        report.done_datetime = timezone.now()
        report.save()

        create_notification(event='report_created', title='Report created', description='The report "%s" is ready.' % report.name, url=uri, report=report, objowner=report.requester)
    except Exception as e:
        report.status = 'error'
        report.save()
        # email_requester(report, uri, error=e)
        # raise e
        log_generic_alert("PDF Report", "Report Creation Failure", "Make sure WKHTMLTOPDF is installed. " + str(e))
    finally:
        if temp is not None:
            # deleting temp xsl file
            temp.close()

    return True


@task(name='add_external_issue_task')
def add_external_issue_task(find, external_issue_provider):
    logger.info("add external issue task")
    add_external_issue(find, external_issue_provider)


@task(name='update_external_issue_task')
def update_external_issue_task(find, old_status, external_issue_provider):
    logger.info("update external issue task")
    update_external_issue(find, old_status, external_issue_provider)


@task(name='close_external_issue_task')
def close_external_issue_task(find, note, external_issue_provider):
    logger.info("close external issue task")
    close_external_issue(find, note, external_issue_provider)


@task(name='reopen_external_issue_task')
def reopen_external_issue_task(find, note, external_issue_provider):
    logger.info("reopen external issue task")
    reopen_external_issue(find, note, external_issue_provider)


@task(name='add_jira_issue_task')
def add_jira_issue_task(find, push_to_jira):
    logger.info("add issue task")
    add_jira_issue(find, push_to_jira)


# @task(name='update_jira_issue_task')
# def update_jira_issue_task(find, push_to_jira):
#     logger.info("update issue task")
#     update_jira_issue(find, push_to_jira)


@task(name='add_epic_task')
def add_epic_task(eng, push_to_jira):
    logger.info("add epic task")
    add_epic(eng, push_to_jira)


@task(name='update_epic_task')
def update_epic_task(eng, push_to_jira):
    logger.info("update epic task")
    update_epic(eng, push_to_jira)


@task(name='close_epic_task')
def close_epic_task(eng, push_to_jira):
    logger.info("close epic task")
    close_epic(eng, push_to_jira)


@task(name='add comment')
def add_comment_task(find, note):
    logger.info("add comment")
    add_comment(find, note)


@app.task(name='async_dedupe')
def async_dedupe(new_finding, *args, **kwargs):
    deduplicationLogger.debug("running async deduplication")
    dedupe_signal.send(sender=new_finding.__class__, new_finding=new_finding)


@app.task(name='applying rules')
def async_rules(new_finding, *args, **kwargs):
    logger.info("applying rules")
    sync_rules(new_finding, *args, **kwargs)


@app.task(name='async_false_history')
def async_false_history(new_finding, *args, **kwargs):
    logger.info("running false_history")
    sync_false_history(new_finding, *args, **kwargs)


@app.task(name='tool_issue_updater')
def async_tool_issue_updater(finding, *args, **kwargs):
    logger.info("running tool_issue_updater")
    tool_issue_updater(finding, *args, **kwargs)


@app.task(bind=True)
def async_update_findings_from_source_issues(*args, **kwargs):
    logger.info("running update_findings_from_source_issues")
    update_findings_from_source_issues()


@app.task(bind=True)
def async_dupe_delete(*args, **kwargs):
    try:
        system_settings = System_Settings.objects.get()
        enabled = system_settings.delete_dupulicates
        dupe_max = system_settings.max_dupes
    except System_Settings.DoesNotExist:
        enabled = False
    if enabled:
        logger.info("delete excess duplicates")
        deduplicationLogger.info("delete excess duplicates")
        findings = Finding.objects \
                .filter(original_finding__duplicate=True) \
                .annotate(num_dupes=Count('original_finding')) \
                .filter(num_dupes__gt=dupe_max)
        for finding in findings:
            duplicate_list = finding.original_finding \
                    .filter(duplicate=True).order_by('date')
            dupe_count = len(duplicate_list) - dupe_max
            for finding in duplicate_list:
                deduplicationLogger.debug('deleting finding {}:{} ({}))'.format(finding.id, finding.title, finding.hash_code))
                finding.delete()
                dupe_count = dupe_count - 1
                if dupe_count == 0:
                    break


@task(name='celery_status', ignore_result=False)
def celery_status():
    return True


@app.task(name='dojo.tasks.async_sla_compute_and_notify')
def async_sla_compute_and_notify_task(*args, **kwargs):
    logger.debug("Computing SLAs and notifying as needed")
    try:
        sla_compute_and_notify(*args, **kwargs)
    except Exception as e:
        logger.error("An unexpected error was thrown calling the SLA code: {}".format(e))
