{% if type == 'mail' %}
    {% load navigation_tags %}
    {% load display_tags %}
    <html>
        <body>
            {% autoescape on %}
                <p>
                    Hello,
                </p>
                <p>
                    {{ description|safe }}
                </p>
                {% if url is not None %}
                    <br/>
                    <br/>
                    More information on this event can be found here: {{ url|full_url }}
                {% endif %}
                <br/>
                <br/>
                    Kind regards, <br/>
                    {% if system_settings.team_name %}
                        {{ system_settings.team_name }}
                    {% else %}
                        Defect Dojo
                    {% endif %}
                <br/>
                <br/>
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
    {{ description|safe }}
{% elif type == 'slack' %}
    {{ description|safe }}
    {% if url is not None %}
        More information on this event can be found here: {{ url|full_url }}
    {% endif %}
    {% if system_settings.disclaimer|length %}

        Disclaimer:
        {{ system_settings.disclaimer }}
    {% endif %}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "Event",
        "summary": "Event",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "{% autoescape on %} {{ description }} {% endautoescape %}"
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
                "name": "View",
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
