from rest_framework import serializers

from dojo.product_attributes.models import VALUE_COMMA_ERROR, Product_Lifecycle, Product_Origin, Product_Platform


class ProductAttributeOptionSerializer(serializers.ModelSerializer):
    class Meta:
        fields = ["id", "value", "name", "icon", "display_order"]

    def validate_value(self, value):
        # Only a new option is checked: an update ignores ``value``, and an existing row keeps its own.
        if self.instance is None and "," in value:
            raise serializers.ValidationError(VALUE_COMMA_ERROR)
        return value

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
