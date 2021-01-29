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
    <p>
    - Day(s) overdue: {{sla}}
    {% else %}
    A security finding is about to breach its SLA.
    <p>
    - Day(s) remaining: {{sla}}
    {% endif %}
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
You can find details here: {{ url|full_url }}
{% elif type == 'msteams' %}
{% url 'view_finding' finding.id as finding_url %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "SLA breached",
        "summary": "SLA breached",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "A SLA for a finding has been breached.",
                "facts": [
                    {
                        "name": "Finding:",
                        "value": "{{ finding.title }}"
                    },
                    {
                        "name": "Severity:",
                        "value": "{{ finding.severity }}"
                    },
                    {
                        "name": "SLA age:",
                        "value": "{{ sla_age }}"
                    }
                ]
            }
        ],
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "View",
            "targets": [
                { "os": "default", "uri": "{{ finding_url|full_url }}" }
                ]
            }
        ]
    }
{% endif %}
