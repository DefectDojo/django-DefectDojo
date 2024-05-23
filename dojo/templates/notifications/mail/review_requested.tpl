{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
<html>
    <body>
        {% autoescape on %}
            {% block description%}
            {% endblock%}
            {% block content %}
                {% block contect_description%}
                    <p>
                            {% blocktranslate trimmed %}
                                User <b>{{ requested_by }}</b> has requested that the following users review the finding <b>{{ finding }}</b> for accuracy:
                            {% endblocktranslate %}
                            {% for user in reviewers %}
                                <li>{{ user.get_full_name }}</li>    
                            {% endfor %}
                    </p>
                {% endblock%}
                {% block event %}
                    It can be reviewed at :
                    <br/>
                    <br/>
                    {% blocktranslate trimmed with event_url=url|full_url%}
                        <center><a href="{{event_url}}" class="proton-button" target="_blank">Go Finding</a></center>
                    {% endblocktranslate %}
                {%endblock%}
            {% endblock %}
        {% endautoescape %}
    </body>
</html>
