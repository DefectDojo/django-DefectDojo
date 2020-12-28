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
{% url 'view_product' test.engagement.product.id as product_url %}
{% url 'view_engagement' test.engagement.id as engagement_url %}
{% url 'view_test' test.id as test_url %}
{{ finding_count }} findings have been updated for while a scan was uploaded: 
<a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a> / <a href="{{ test_url|full_url }}">{{ test }}</a><br/>
<br/>
<p>
New findings:<br/>
{% for finding in findings_new %}
{% url 'view_finding' finding.id as finding_url %}
<a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
{% empty %}
None<br/>
{% endfor %}
</p>
<p>
Reactivated findings:<br/>
{% for finding in findings_reactivated %}
{% url 'view_finding' finding.id as finding_url %}
<a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
None<br/>
{% empty %}
{% endfor %}
</p>
<p>
Closed findings:<br/>
{% for finding in findings_mitigated %}
{% url 'view_finding' finding.id as finding_url %}
<a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
{% empty %}
None<br/>
{% endfor %}
</p>
<p>
Untouched findings:<br/>
{% for finding in findings_untouched %}
{% url 'view_finding' finding.id as finding_url %}
<a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
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
</html>
{% elif type == 'alert' %}
{{ description }}
{% elif type == 'slack' %}
{{ description }}

{% if url is not None %}
{{ test }} results have been uploaded.
They can be viewed here: {{ url|full_url }}
{% endif %}
{% elif type == 'msteams' %}
{% url 'view_test' test.id as test_url %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "Scan added",
        "summary": "Scan added",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "A new scan has been added.",
                "facts": [
                    {
                        "name": "Product:",
                        "value": "{{ test.engagement.product.name }}"
                    },
                    {
                        "name": "Engagement:",
                        "value": "{{ test.engagement.name }}"
                    },
                    {
                        "name": "Scan:",
                        "value": "{{ test }}"
                    }
                ]
            }
        ],
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "View",
            "targets": [
                { "os": "default", "uri": "{{ test_url|full_url }}" }
                ]
            }
        ]
    }
{% endif %}
