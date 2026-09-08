from rest_framework import serializers

from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform


class ProductAttributeOptionSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ["id", "value", "name", "icon", "display_order"]

    def update(self, instance, validated_data):
        # ``value`` is the stable machine key that the Product foreign key, imports,
        # exports and automation rules depend on. It is immutable once created, so any
        # attempt to change it on an existing option is ignored.
        validated_data.pop("value", None)
        return super().update(instance, validated_data)


class ProductPlatformSerializer(ProductAttributeOptionSerializer):
    class Meta(ProductAttributeOptionSerializer.Meta):
        model = Product_Platform


class ProductLifecycleSerializer(ProductAttributeOptionSerializer):
    class Meta(ProductAttributeOptionSerializer.Meta):
        model = Product_Lifecycle


class ProductOriginSerializer(ProductAttributeOptionSerializer):
    class Meta(ProductAttributeOptionSerializer.Meta):
        model = Product_Origin
