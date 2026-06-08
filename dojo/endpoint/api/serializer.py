import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from rest_framework import serializers
from rest_framework.exceptions import ValidationError as RestFrameworkValidationError

from dojo.endpoint.models import Endpoint, Endpoint_Params, Endpoint_Status
from dojo.endpoint.utils import endpoint_filter, endpoint_meta_import
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.location.models import Location
from dojo.models import Product, get_current_date
from dojo.utils import is_scan_file_too_large

logger = logging.getLogger(__name__)


class EndpointStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint_Status
        fields = "__all__"

    def run_validators(self, initial_data):
        try:
            return super().run_validators(initial_data)
        except RestFrameworkValidationError as exc:
            if "finding, endpoint must make a unique set" in str(exc):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg) from exc
            raise

    def create(self, validated_data):
        endpoint = validated_data.get("endpoint")
        finding = validated_data.get("finding")
        try:
            status = Endpoint_Status.objects.create(
                finding=finding, endpoint=endpoint,
            )
        except IntegrityError as ie:
            if "finding, endpoint must make a unique set" in str(ie):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg)
            raise
        status.mitigated = validated_data.get("mitigated", False)
        status.false_positive = validated_data.get("false_positive", False)
        status.out_of_scope = validated_data.get("out_of_scope", False)
        status.risk_accepted = validated_data.get("risk_accepted", False)
        status.date = validated_data.get("date", get_current_date())
        status.save()
        return status

    def update(self, instance, validated_data):
        try:
            return super().update(instance, validated_data)
        except IntegrityError as ie:
            if "finding, endpoint must make a unique set" in str(ie):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg)
            raise


class EndpointSerializer(serializers.ModelSerializer):
    # tags field uses lazy get_fields() to break the import cycle:
    # EndpointSerializer -> TagListSerializerField -> api_v2.serializers -> EndpointSerializer
    active_finding_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Endpoint
        exclude = ("inherited_tags",)

    def get_fields(self):
        fields = super().get_fields()
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields["tags"] = TagListSerializerField(required=False)
        return fields

    def validate(self, data):

        if self.context["request"].method != "PATCH":
            if "product" not in data:
                msg = "Product is required"
                raise serializers.ValidationError(msg)
            protocol = data.get("protocol")
            userinfo = data.get("userinfo")
            host = data.get("host")
            port = data.get("port")
            path = data.get("path")
            query = data.get("query")
            fragment = data.get("fragment")
            product = data.get("product")
        else:
            protocol = data.get("protocol", self.instance.protocol)
            userinfo = data.get("userinfo", self.instance.userinfo)
            host = data.get("host", self.instance.host)
            port = data.get("port", self.instance.port)
            path = data.get("path", self.instance.path)
            query = data.get("query", self.instance.query)
            fragment = data.get("fragment", self.instance.fragment)
            if "product" in data and data["product"] != self.instance.product:
                msg = "Change of product is not possible"
                raise serializers.ValidationError(msg)
            product = self.instance.product

        endpoint_ins = Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            product=product,
        )
        endpoint_ins.clean()  # Run standard validation and clean process; can raise errors

        endpoint = endpoint_filter(
            protocol=endpoint_ins.protocol,
            userinfo=endpoint_ins.userinfo,
            host=endpoint_ins.host,
            port=endpoint_ins.port,
            path=endpoint_ins.path,
            query=endpoint_ins.query,
            fragment=endpoint_ins.fragment,
            product=endpoint_ins.product,
        )
        if (
            self.context["request"].method in {"PUT", "PATCH"}
            and (
                (endpoint.count() > 1)
                or (
                    endpoint.count() == 1
                    and endpoint.first().pk != self.instance.pk
                )
            )
        ) or (
            self.context["request"].method == "POST" and endpoint.count() > 0
        ):
            msg = (
                "It appears as though an endpoint with this data already "
                "exists for this product."
            )
            raise serializers.ValidationError(msg, code="invalid")

        # use clean data
        data["protocol"] = endpoint_ins.protocol
        data["userinfo"] = endpoint_ins.userinfo
        data["host"] = endpoint_ins.host
        data["port"] = endpoint_ins.port
        data["path"] = endpoint_ins.path
        data["query"] = endpoint_ins.query
        data["fragment"] = endpoint_ins.fragment
        data["product"] = endpoint_ins.product

        return data


class EndpointParamsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint_Params
        fields = "__all__"


class EndpointMetaImporterSerializer(serializers.Serializer):
    file = serializers.FileField(required=True)
    create_endpoints = serializers.BooleanField(default=True, required=False)
    create_tags = serializers.BooleanField(default=True, required=False)
    create_dojo_meta = serializers.BooleanField(default=False, required=False)
    product_name = serializers.CharField(required=False)
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=False,
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    product_id = serializers.IntegerField(read_only=True)

    def validate(self, data):
        file = data.get("file")
        if file and is_scan_file_too_large(file):
            msg = f"Report file is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)

        return data

    def save(self):
        data = self.validated_data
        file = data.get("file")
        create_endpoints = data.get("create_endpoints", True)
        create_tags = data.get("create_tags", True)
        create_dojo_meta = data.get("create_dojo_meta", False)
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create.process_import_meta_data_from_dict(data)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**data)
            if not product:
                product = auto_create.get_target_product_by_id_if_exists(**data)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))
        try:
            if settings.V3_FEATURE_LOCATIONS:
                endpoint_meta_import(
                    file,
                    product,
                    create_endpoints,
                    create_tags,
                    create_dojo_meta,
                    origin="API",
                    object_class=Location,
                )
            else:
                # TODO: Delete this after the move to Locations
                endpoint_meta_import(
                    file,
                    product,
                    create_endpoints,
                    create_tags,
                    create_dojo_meta,
                    origin="API",
                )
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)
