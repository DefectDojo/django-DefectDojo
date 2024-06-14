{% if product %}
{% include 'notifications/webhooks/subtemplates/product.tpl' with product=product %}
{% else %}
{% include 'notifications/webhooks/subtemplates/product.tpl' with product=engagement.product %}
{% endif %}
engagement: {{ engagement.name }}
engagement_id: {{ engagement.pk }}
