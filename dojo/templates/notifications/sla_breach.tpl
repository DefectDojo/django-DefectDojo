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
    {% if sla_age < 0 %}
    This security finding has breached its SLA.
    {% days_status_verb = 'overdue' %}
    {% else %}
    A security finding is about to breach its SLA.
    {% days_status_verb = 'remaining' %}
    {% endif %}

    <p>
    - Days {{ days_status_verb }}: {{abs(sla_age)}}
    <br/>
    - Title: <a href="{{finding_url|full_url}}">{{finding.title}}</a>
    <br/>
    - Severity: {{finding.severity}}
    <br/><br/>
    </p>
    Please refer to your SLA documentation for further guidance.
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
</html>
{% elif type == 'alert' %}
    SLA breach alert for finding {{ finding.id }}. Relative days count to SLA due date: {{sla_age}}.
{% elif type == 'slack' %}
    SLA breach alert for finding {{ finding.id }}. Relative days count to SLA due date: {{sla_age}}.
Title: {{finding.title}}
Severity: {{finding.severity}}
You can find details here: {{ url }}
{% endif %}