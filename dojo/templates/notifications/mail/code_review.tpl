{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% block description%}
{% endblock%}
{% block contect%}
    {% block contect_description %}
        {% blocktranslate trimmed %}
            User <review> {{review}} review completed the finding {{finding.title}} for accuracy: 
            <br>
            <br>
            {{new_note}}
            <br>
            <br>
        {% endblocktranslate %}
    {% endblock %}
    {% block event %}
            It can be reviewed at :
            <br/>
            <br/>
            {% blocktranslate trimmed with event_url=url|full_url%}
                <center><a href="{{event_url}}" class="proton-button" target="_blank">Go Finding</a></center>
            {% endblocktranslate %}
    {%endblock%}
{% endblock%}
