from django.contrib import admin

from dojo.file_uploads.models import FileAccessToken, FileUpload

admin.site.register(FileUpload)
admin.site.register(FileAccessToken)
