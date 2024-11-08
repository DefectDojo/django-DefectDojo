{% load display_tags %}
{% if product %}
{% include 'notifications/webhooks/subtemplates/product.tpl' with product=product %}
{% else %}
{% include 'notifications/webhooks/subtemplates/product.tpl' with product=engagement.product %}
{% endif %}
{% url 'view_engagement' engagement.id as engagement_url_ui %}
{% url 'engagement-detail' engagement.id as engagement_url_api %}
engagement:
    name: {{ engagement.name | default_if_none:'' }}
    id: {{ engagement.pk }}
    url_ui: {{ engagement_url_ui|full_url }}
    url_api: {{ engagement_url_api|full_url }}
