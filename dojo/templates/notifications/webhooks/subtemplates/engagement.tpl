{% if product %}
{% include 'notifications/webhooks/subtemplates/product.tpl' with product=product %}
{% else %}
{% include 'notifications/webhooks/subtemplates/product.tpl' with product=engagement.product %}
{% endif %}
engagement:
    name: {{ engagement.name }}
    id: {{ engagement.pk }}
