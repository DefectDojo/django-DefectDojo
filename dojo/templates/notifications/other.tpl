{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
    Hello,

    {{ description|safe }}{% if url is not None %}
    More information on this event can be found here: {{ url|full_url }}
    {% endif %}

    Kind regards,
    {% if system_settings.team_name and system_settings.team_name %}
        {{ system_settings.team_name }}
    {% else %}
        Defect Dojo
    {% endif %}

    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
        <br/>
        <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
            <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">Disclaimer</span><br/>
            <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer }}</p>
        </div>
    {% endif %}
{% elif type == 'alert' %}
    {{ description|safe }}
{% elif type == 'slack' %}
    {{ description|safe }}
    {% if url is not None %}
        More information on this event can be found here: {{ url|full_url }}
    {% endif %}
    {% if system_settings.disclaimer is not None %}
        
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
