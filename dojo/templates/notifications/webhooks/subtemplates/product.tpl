{% if product_type %}
{% include 'notifications/webhooks/subtemplates/product_type.tpl' with product_type=product_type %}
{% else %}
{% include 'notifications/webhooks/subtemplates/product_type.tpl' with product_type=product.prod_type %}
{% endif %}
product: {{ product.name }}
product_id: {{ product.pk }}
