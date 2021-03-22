{% if type == 'mail' %}
    Hello,

    User {{ user }} jotted a note on {{ section }}:

    {{ note }}

    It can be reviewed at {{ url }}

    Kind regards,
    {% if system_settings.team_name and system_settings.team_name %}
        {{ system_settings.team_name }}
    {% else %}
        Defect Dojo
    {% endif %}
    <br/>
    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
        <br/>
        <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
            <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">Disclaimer</span><br/>
            <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer }}</p>
        </div>
    {% endif %}
{% elif type == 'alert' %}
    User {{ user }} jotted a note on {{ section }}:

    {{ note }}
{% elif type == 'slack' %}
    User {{ user }} jotted a note on {{ section }}:

    {{ note }}
    
    Full details of the note can be reviewed at {{ url }}
    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
        
        Disclaimer:
        {{ system_settings.disclaimer }}
    {% endif %}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "User Mentioned",
        "summary": "User Mentioned",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "A user has been mentioned.",
                "facts": [
                    {
                        "name": "User:",
                        "value": "{{ user }}"
                    },
                    {
                        "name": "Section:",
                        "value": "{{ section }}"
                    },
                    {
                        "name": "note:",
                        "value": "{{ note }}"
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