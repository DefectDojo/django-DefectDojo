{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
<html>
<body>
{% autoescape on %}
<p>
Hello {{ user.get_full_name }},
<br/>
{{ description }}<br/>
<br/>
{% if finding_count is not None %}
{{ finding_count }} findings have updated for '{{product}} / {{ engagement.name }} / {{ test }}': <a href="{{ full_url }}">findings</a><br/>
{% else %}
findings have updated for '{{product}} / {{ engagement.name }} / {{ test }}': <a href="{{ full_url }}">findings</a><br/>
{% endif %}
<br/>
<p>
New findings:<br/>
{% for finding in findings_new %}
{% url 'view_finding' finding.id as finding_url %}
({{ finding.severity }}) <a href="{{ finding_url|full_url }}">{{ finding.title }}</a><br/>
{% empty %}
None<br/>
{% endfor %}
</p>
<p>
Reactivated findings:<br/>
{% for finding in findings_reactivated %}
{% url 'view_finding' finding.id as finding_url %}
({{ finding.severity }}) <a href="{{ finding_url|full_url }}">{{ finding.title }}</a><br/>
{% empty %}
None<br/>
{% endfor %}
</p>
<p>
Closed findings:<br/>
{% for finding in findings_mitigated %}
{% url 'view_finding' finding.id as finding_url %}
({{ finding.severity }}) <a href="{{ finding_url|full_url }}">{{ finding.title }}</a><br/>
{% empty %}
None<br/>
{% endfor %}
</p>
<br/>
<br/>
Kind regards,<br/>
<br/>
{% if system_settings.team_name is not None %}
{{ system_settings.team_name }}
{% else %}
Defect Dojo
{% endif %}
<p>
<br/>
<br/>
<p>
{% url 'notifications' as notification_url %}
You can manage your notification settings here: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
</p>
{% endautoescape %}
</body>
<html>
{% elif type == 'alert' %}
{{ description }}
{% elif type == 'slack' %}
{{ description }}

{% if url is not None %}
{{ test }} results have been uploaded.
They can be viewed here: {{ url }}
{% endif %}
{% endif %}
