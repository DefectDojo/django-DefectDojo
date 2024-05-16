
{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% block content %}
    {% if url is not None %}
        {% block event %}
            More information on this event can be found here:
            {% blocktranslate trimmed with event_url=url|full_url %}
            <center><a href="{{event_url}}" class="proton-button" target="_blank">Go Findinge/a></center>
            {% endblocktranslate %}
        {% endblock%}
    {% endif %}
{% endblock %}
