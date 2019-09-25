import json
import googleapiclient.discovery
from google.oauth2 import service_account

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib import messages

from dojo.models import Finding, System_Settings
from dojo.forms import GoogleSheetFieldsForm
from dojo.utils import add_breadcrumb

def connect_to_google_apis(request):
    SCOPES = ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/spreadsheets']
    system_settings=get_object_or_404(System_Settings, id=1)
    service_account_info = json.loads(system_settings.credentials)
    credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=SCOPES)
    sheets_service = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
    drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)
    #Test the sheets API by creating s spreadsheet
    spreadsheet = {
    'properties': {
        'title': 'Test spreadsheet'
        }
    }
    spreadsheet = sheets_service.spreadsheets().create(body=spreadsheet, fields='spreadsheetId').execute()
    spreadsheetId = spreadsheet.get('spreadsheetId')
    #Test the drive API
    system_settings = get_object_or_404(System_Settings, id=1)
    folder_id = system_settings.drive_folder_ID
    file = drive_service.files().get(fileId=spreadsheetId, fields='parents').execute() # Retrieve the existing parents to remove
    previous_parents = ",".join(file.get('parents'))
    file = drive_service.files().update(fileId=spreadsheetId,                          # Move the file to the new folder
                                        addParents=folder_id,
                                        removeParents=previous_parents,
                                        fields='id, parents').execute()
    drive_service.files().delete(fileId=spreadsheetId).execute()                       #Delete test spredsheet
    messages.add_message(
        request,
        messages.SUCCESS,
        "Google drive configuration successful.",
        extra_tags="alert-success",
    )
    return HttpResponseRedirect(reverse('dashboard'))


def configure_google_drive(request):
    fields = Finding._meta.fields
    form = GoogleSheetFieldsForm(all_fields=fields)
    if request.method=='POST':
        form = GoogleSheetFieldsForm(request.POST, request.FILES, all_fields=fields)
        if form.is_valid():
            #Save column width to database
            cleaned_data = form.cleaned_data
            column_widths=''
            for i in fields:
                column_widths += str(cleaned_data[i.name]) + ','
            column_widths = column_widths[:-1]
            system_settings=get_object_or_404(System_Settings, id=1)
            system_settings.column_widths=column_widths

            #Save uploaded json file in database
            cred_file = request.FILES['cred_file']
            cred_byte=cred_file.read() #read data from the temporary uploaded file
            cred_str = cred_byte.decode('utf8') #convert bytes object to string
            system_settings.credentials=cred_str

            #Save the google drive folder url in database
            drive_folder_ID = form.cleaned_data['drive_folder_ID']
            system_settings.drive_folder_ID=drive_folder_ID
            system_settings.save()
            return redirect ('connect_to_google_apis')
    add_breadcrumb(title="Google Sheet Configuration", top_level=False, request=request)
    return render(request, 'dojo/google_sheet_configuration.html', {
        'name': 'Google Sheet Configuration',
        'metric': False,
        'form':form,
    })
