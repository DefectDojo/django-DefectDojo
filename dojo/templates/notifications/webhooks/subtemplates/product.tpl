{% if product_type %}
{% include 'notifications/webhooks/subtemplates/product_type.tpl' with product_type=product_type %}
{% else %}
{% include 'notifications/webhooks/subtemplates/product_type.tpl' with product_type=product.prod_type %}
{% endif %}
product:
    name: {{ product.name | default_if_none:'' }}
    id: {{ product.pk }}
