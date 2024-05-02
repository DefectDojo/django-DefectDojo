# #  product
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render

from dojo.forms import SystemSettingsForm
from dojo.models import System_Settings
from dojo.utils import add_breadcrumb, get_celery_worker_status

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_superuser)
def system_settings(request):
    system_settings_obj = System_Settings.objects.get(no_cache=True)
    form = SystemSettingsForm(instance=system_settings_obj)

    sections = [
        {
            'name': 'Deduplication and Finding Settings',
            'fields': {'enable_deduplication', 'delete_duplicates', 'max_dupes', 'false_positive_history',
                       'retroactive_false_positive_history', 'risk_acceptance_form_default_days',
                       'risk_acceptance_notify_before_expiration', 'enable_finding_groups',
                       'enable_endpoint_metadata_import', 'enable_template_match'}
        },
        {
            'name': 'Finding Service Level Agreement (SLA) Settings',
            'fields': {'enable_finding_sla', 'enable_notify_sla_active', 'enable_notify_sla_active_verified',
                       'enable_notify_sla_jira_only', 'enable_notify_sla_exponential_backoff',
                       'enable_similar_findings'}
        },
        {
            'name': 'Jira Integration Settings',
            'fields': {'enable_jira', 'jira_labels', 'add_vulnerability_id_to_jira_label', 'enable_jira_web_hook',
                       'disable_jira_webhook_secret', 'jira_webhook_secret', 'jira_minimum_severity'}
        },
        {
            'name': 'Integration Settings',
            'fields': {'enable_github', 'enable_slack_notifications', 'slack_channel', 'slack_token', 'slack_username',
                       'enable_msteams_notifications', 'msteams_url', 'email_from', 'enable_mail_notifications',
                       'mail_notifications_to'}
        },
        {
            'name': 'Product Settings',
            'fields': {'enable_product_grade', 'product_grade_a', 'product_grade_b', 'product_grade_c',
                       'product_grade_d', 'product_grade_e', 'product_grade_f', 'enable_benchmark',
                       'enable_product_tag_inheritance', 'enable_product_tracking_files'}
        },
        {
            'name': 'Engagement Settings',
            'fields': {'engagement_auto_close', 'engagement_auto_close_days'}
        },
        {
            'name': 'Application Settings',
            'fields': {'enable_credentials', 'credentials', 'disclaimer', 'url_prefix', 'team_name', 'time_zone',
                       'allow_anonymous_survey_repsonse', 'enable_questionnaires', 'enable_checklists',
                       'enable_calendar', 'enable_user_profile_editable', 'default_group', 'default_group_role',
                       'default_group_email_pattern'}
        },
        {
            'name': 'Password Settings',
            'fields': {'minimum_password_length', 'maximum_password_length', 'number_character_required',
                       'special_character_required', 'lowercase_character_required', 'uppercase_character_required',
                       'non_common_password_required'}
        }
    ]

    all_fields = {field.name for field in form.visible_fields()}
    fields_with_section = {field for section in sections for field in section['fields']}
    fields_without_section = all_fields - fields_with_section
    sections.append({'name': 'Other', 'fields': fields_without_section})

    """
    **** To be Finished JIRA Status info ****
    jira_bool = True
    jira_msg = 'None'
    if not celery_bool:
        jira_bool = False
        jira_msg = 'Celery is not working properly'
    else:

        try:
            jira_server = jform.cleaned_data.get('url').rstrip('/')
            jira = JIRA(server=jform.cleaned_data.get('url').rstrip('/'),
                        basic_auth=(jform.cleaned_data.get('username'), jform.cleaned_data.get('password')))
            new_j = jform.save(commit=False)
            new_j.url = jira_server
            new_j.save()
            messages.add_message(request,
                                 messages.SUCCESS,

                                 'JIRA Configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('jira', ))
        except:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Unable to authenticate to JIRA. Please check the URL, username, and password.',
                                 extra_tags='alert-danger')

    """

    if request.method == 'POST':
        form = SystemSettingsForm(request.POST, instance=system_settings_obj)
        if form.is_valid():
            if (form.cleaned_data['default_group'] is None and form.cleaned_data['default_group_role'] is not None) or \
               (form.cleaned_data['default_group'] is not None and form.cleaned_data['default_group_role'] is None):
                messages.add_message(request,
                    messages.WARNING,
                    'Settings cannot be saved: Default group and Default group role must either both be set or both be empty.',
                    extra_tags='alert-warning')
            elif form.cleaned_data['minimum_password_length'] >= form.cleaned_data['maximum_password_length']:
                messages.add_message(request,
                    messages.WARNING,
                    'Settings cannot be saved: Minimum required password length must be less than maximum required password length.',
                    extra_tags='alert-warning')
            elif form.cleaned_data['enable_deduplication'] is True and form.cleaned_data['false_positive_history'] is True:
                messages.add_message(request,
                    messages.WARNING,
                    'Settings cannot be saved: Deduplicate findings and False positive history can not be set at the same time.',
                    extra_tags='alert-warning')
            elif form.cleaned_data['retroactive_false_positive_history'] is True and form.cleaned_data['false_positive_history'] is False:
                messages.add_message(request,
                    messages.WARNING,
                    'Settings cannot be saved: Retroactive false positive history can not be set without False positive history.',
                    extra_tags='alert-warning')
            else:
                form.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'Settings saved.',
                                    extra_tags='alert-success')
        return render(request, 'dojo/system_settings.html', {'form': form, 'sections': sections})

    else:
        # Celery needs to be set with the setting: CELERY_RESULT_BACKEND = 'db+sqlite:///dojo.celeryresults.sqlite'
        if hasattr(settings, 'CELERY_RESULT_BACKEND'):
            # Check the status of Celery by sending calling a celery task
            celery_bool = get_celery_worker_status()

            if celery_bool:
                celery_msg = "Celery is processing tasks."
                celery_status = "Running"
            else:
                celery_msg = "Celery does not appear to be up and running. Please ensure celery is running."
                celery_status = "Not Running"
        else:
            celery_bool = False
            celery_msg = "Celery needs to have the setting CELERY_RESULT_BACKEND = 'db+sqlite:///dojo.celeryresults.sqlite' set in settings.py."
            celery_status = "Unknown"

    add_breadcrumb(title="Application settings", top_level=False, request=request)
    return render(request, 'dojo/system_settings.html',
                  {'form': form,
                    'sections': sections,
                   'celery_bool': celery_bool,
                   'celery_msg': celery_msg,
                   'celery_status': celery_status})
