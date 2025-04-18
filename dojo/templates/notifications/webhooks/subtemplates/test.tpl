{% load display_tags %}
{% if engagement %}
{% include 'notifications/webhooks/subtemplates/engagement.tpl' with engagement=engagement %}
{% else %}
{% include 'notifications/webhooks/subtemplates/engagement.tpl' with engagement=test.engagement %}
{% endif %}
{% url 'view_test' test.id as test_url_ui %}
{% url 'test-detail' test.id as test_url_api %}
test:
    title: {{ test.title | default_if_none:'' | tojson(0) }}
    id: {{ test.pk }}
    url_ui: {{ test_url_ui | full_url | tojson(0) }}
    url_api: {{ test_url_api | full_url | tojson(0) }}
