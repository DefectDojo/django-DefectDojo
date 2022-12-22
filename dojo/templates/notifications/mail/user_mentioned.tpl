{% load navigation_tags %}
{% load display_tags %}
<html>
    <body>
        {% autoescape on %}
            <p>
                Hello,
            </p>
            <p>
                User {{ user }} jotted a note on {{ section }}:<br/>
                <br/>
                {{ note }}<br/>
                <br/>
                It can be reviewed at {{ url }}
            </p>

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
