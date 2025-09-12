
{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% block content%}
     <p>
        <br/><br/>
        {% blocktranslate %}{{ finding_count }} findings have been updated for while a scan was uploaded{% endblocktranslate %}:
        {% url 'view_product_type' test.engagement.product.prod_type.id as product_type_url %}
        {% url 'view_product' test.engagement.product.id as product_url %}
        {% url 'view_engagement' test.engagement.id as engagement_url %}
        {% url 'view_test' test.id as test_url %}
        <a href="{{product_type_url|full_url}}">{{product_type}}</a> / <a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a> / <a href="{{ test_url|full_url }}">{{ test }}</a><br/>
        <br/>
        <details>
        <summary>{% blocktranslate %}New findings{% endblocktranslate %} ({{ findings_new | length }})</summary><br/>
        {% for finding in findings_new %}
            {% url 'view_finding' finding.id as finding_url %}
            <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
        {% empty %}
            {% trans "None" %}<br/>
        {% endfor %}
        </details>
    </p>
    <p>
        <details>
        <summary>{% blocktranslate %}Reactivated findings{% endblocktranslate %} ({{ findings_reactivated | length }})</summary><br/>
        {% for finding in findings_reactivated %}
            {% url 'view_finding' finding.id as finding_url %}
            <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
        {% empty %}
            {% trans "None" %}<br/>
        {% endfor %}
        </details>
    </p>
    <p>
        <details>
        <summary>{% blocktranslate %}Closed findings{% endblocktranslate %} ({{ findings_mitigated | length }})</summary><br/>
        {% for finding in findings_mitigated %}
            {% url 'view_finding' finding.id as finding_url %}
            <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
        {% empty %}
            {% trans "None" %}<br/>
        {% endfor %}
        </details>
    </p>
    <p>
        <details>
        <summary>{% blocktranslate %}Untouched findings{% endblocktranslate %} ({{ findings_untouched | length }})</summary><br/>
        {% for finding in findings_untouched %}
            {% url 'view_finding' finding.id as finding_url %}
            <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }})<br/>
        {% empty %}
            {% trans "None" %}<br/>
        {% endfor %}
        </details>
    </p>
{%endblock%}
