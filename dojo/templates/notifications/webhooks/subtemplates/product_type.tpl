product_type:
    name: {{ product_type.name | default_if_none:'' }}
    id: {{ product_type.pk }}
