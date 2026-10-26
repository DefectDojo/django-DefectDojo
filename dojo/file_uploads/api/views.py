from rest_framework import status
from rest_framework.response import Response

from dojo.file_uploads.api.serializer import FileSerializer


def related_file_detail_response(request, obj, file_id, object_name):
    """
    Update (PATCH) or delete (DELETE) one file attached to an Engagement, Test or Finding.

    ``obj`` must come from the viewset's ``get_object()``, so the object permission
    check for the request method has already run. Only files attached to ``obj``
    can be changed; any other file ID returns 404.
    """
    file_object = obj.files.filter(id=file_id).first()
    if file_object is None:
        return Response(
            {"error": f"File ID not associated with {object_name}"},
            status=status.HTTP_404_NOT_FOUND,
        )

    if request.method == "DELETE":
        # FileUpload.delete() also removes the file from storage
        file_object.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    serialized_file = FileSerializer(file_object, data=request.data, partial=True)
    if not serialized_file.is_valid():
        return Response(serialized_file.errors, status=status.HTTP_400_BAD_REQUEST)
    # A replaced file is removed from storage by the FileUpload pre_save signal
    serialized_file.save()
    return Response(serialized_file.data, status=status.HTTP_200_OK)
