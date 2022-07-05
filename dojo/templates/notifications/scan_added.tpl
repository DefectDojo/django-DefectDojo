{% if type == 'mail' %}
    {% load navigation_tags %}
    {% load display_tags %}
    {% url 'view_product' test.engagement.product.id as product_url %}
    {% url 'view_engagement' test.engagement.id as engagement_url %}
    {% url 'view_test' test.id as test_url %}
    <html>
        <body>
            {% autoescape on %}
                <p>
                    Hello {{ user.get_full_name }},
                </p>
                <p>
                    {{ description }}
                    <br/><br/>
                    {{ finding_count }} findings have been updated for while a scan was uploaded:
                    <a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a> / <a href="{{ test_url|full_url }}">{{ test }}</a><br/>
                    <br/>
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
                    {% empty %}
                        None<br/>
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
                <br/><br/>
                    Kind regards,
                <br/><br/>
                {% if system_settings.team_name %}
                    {{ system_settings.team_name }}
                {% else %}
                    Defect Dojo
                {% endif %}
                <br/><br/>
                <p>
                    {% url 'notifications' as notification_url %}
                    You can manage your notification settings here: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
                </p>
                {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
                    <br/>
                    <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
                        <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">Disclaimer</span><br/>
                        <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer }}</p>
                    </div>
                {% endif %}
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
    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
        
        Disclaimer:
        {{ system_settings.disclaimer }}
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
            {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
                ,{
                    "activityTitle": "Disclaimer",
                    "text": "{{ system_settings.disclaimer }}"
                }
            {% endif %}
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "View Test",
                "targets": [
                    {
                        "os": "default",
                        "uri": "{{ url|full_url }}"
                    }
                ]
            }
        ]
    }
{% endif %}
