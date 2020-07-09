{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
<html>
<body>
{% autoescape on %}
<p>
Hello {{ user.get_full_name }},
<br/>
<br/>
{% url 'view_finding' finding.id as finding_url %}
    A security finding is about to breach its SLA.
    <p>
    - Days remaining: {{sla_age}}
    <br/>
    - Title: <a href="{{finding_url|full_url}}">{{finding.title}}</a>
    <br/>
    - Severity: {{finding.severity}}
    <br/><br/>
    </p>
    Please refer to the SLA documentation.
<br/></br>
Kind regards,
</br></br>
{% if system_settings.team_name is not None %}
{{ system_settings.team_name }}</br>
{% else %}
Defect Dojo</br>
{% endif %}
<p>
{% endautoescape %}
</body>
<html>
{% elif type == 'alert' %}
    SLA breach alert for finding {{ finding.id }}. {{sla_age}} days left.
{% elif type == 'slack' %}
    SLA breach alert for finding {{ finding.id }}. {{sla_age}} days left.
Title: {{finding.title}}
You can find details here: {{ url }}
{% endif %}