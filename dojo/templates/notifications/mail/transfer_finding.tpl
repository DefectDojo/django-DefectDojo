{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% block content %}
    {% for transfer_finding_finding in transfer_finding.transfer_findings.all %}
        {% url 'view_finding_render' transfer_finding_finding.findings.id transfer_finding.id as finding_url %}
        <li>
            <a href="{{ finding_url|full_url }}">{{ transfer_finding_finding.findings.title }}</a> ({{ transfer_finding_finding.findings.severity }}) {{ transfer_finding_finding.findings |finding_display_status:"email" }}
            <br/>
            <br/>
        </li>
    {% endfor %}
    {% if url is not None %}
        {% block event %}
            More information on this event can be found here:
            <br/>
            <br/>
            {% blocktranslate trimmed with event_url=url|full_url %}
            <center><a href="{{event_url}}" class="proton-button" target="_blank">Go Transfer Finding</a></center>
            {% endblocktranslate %}
        {% endblock%}
    {% endif %}
{% endblock %}
