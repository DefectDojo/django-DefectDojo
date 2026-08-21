{% load display_tags %}
{% load as_json %}
{% if engagement %}
{% include 'notifications/webhooks/subtemplates/engagement.tpl' with engagement=engagement %}
{% else %}
{% include 'notifications/webhooks/subtemplates/engagement.tpl' with engagement=test.engagement %}
{% endif %}
{% url 'view_test' test.id as test_url_ui %}
{% url 'test-detail' test.id as test_url_api %}
test:
    title: {{ test.title |  as_json_no_html_esc }}
    id: {{ test.pk }}
    url_ui: {{ test_url_ui | full_url | as_json_no_html_esc }}
    url_api: {{ test_url_api | full_url | as_json_no_html_esc }}
