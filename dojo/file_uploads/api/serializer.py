from rest_framework import serializers

from dojo.file_uploads.models import FileUpload


class FileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = FileUpload
        fields = "__all__"

    def validate(self, data):
        if file := data.get("file"):
            # the clean will validate the file extensions and raise a Validation error if the extensions are not accepted
            FileUpload(title=file.name, file=file).clean()
            return data
        return None


class RawFileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = FileUpload
        fields = ["file"]
