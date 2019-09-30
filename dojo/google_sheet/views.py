import json
import googleapiclient.discovery
from googleapiclient.errors import HttpError
from google.oauth2 import service_account

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib import messages

from dojo.models import Finding, System_Settings, Test, Engagement, Product
from dojo.forms import GoogleSheetFieldsForm
from dojo.utils import add_breadcrumb

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
            cred_byte=cred_file.read()                          #read data from the temporary uploaded file
            cred_str = cred_byte.decode('utf8')                 #convert bytes object to string
            system_settings.credentials=cred_str

            #Save the google drive folder ID in database
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


def connect_to_google_apis(request):
    SCOPES = ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/spreadsheets']
    system_settings=get_object_or_404(System_Settings, id=1)
    service_account_info = json.loads(system_settings.credentials)
    try:
        #Validate the uploaded credentials file
        credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=SCOPES)
    except ValueError :
        print ('Invalid credentials file')
        messages.add_message(
            request,
            messages.ERROR,
            'Invalid credentials file.',
            extra_tags='alert-danger')
        return redirect('configure_google_drive')
    else:
        sheets_service = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
        drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)
        spreadsheet = {
        'properties': {
            'title': 'Test spreadsheet'
            }
        }
        try:
            #Check the sheets API is enabled or not
            spreadsheet = sheets_service.spreadsheets().create(body=spreadsheet, fields='spreadsheetId').execute()
        except googleapiclient.errors.HttpError:
            messages.add_message(
                request,
                messages.ERROR,
                'Enable the sheets API from the google developer console.',
                extra_tags='alert-danger')
            return redirect('configure_google_drive')
        else:
            spreadsheetId = spreadsheet.get('spreadsheetId')
            try:
                #Check the drive API is enabled or not
                file = drive_service.files().get(fileId=spreadsheetId, fields='parents').execute() # Retrieve the existing parents to remove
            except googleapiclient.errors.HttpError:
                messages.add_message(
                    request,
                    messages.ERROR,
                    'Enable the drive API from the google developer console.',
                    extra_tags='alert-danger')
                return redirect('configure_google_drive')
            else:
                previous_parents = ",".join(file.get('parents'))
                system_settings = get_object_or_404(System_Settings, id=1)
                folder_id = system_settings.drive_folder_ID
                try:
                    #Validate the drive folder id and it's permissions
                    file = drive_service.files().update(fileId=spreadsheetId,              # Move the file to the new folder
                                                        addParents=folder_id,
                                                        removeParents=previous_parents,
                                                        fields='id, parents').execute()
                except googleapiclient.errors.HttpError as error:
                    if error.resp.status == 403:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            'Application does not have write access to the given google drive folder',
                            extra_tags='alert-danger')
                    if error.resp.status == 404:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            'Google drive folder ID is invalid',
                            extra_tags='alert-danger')
                    return redirect('configure_google_drive')
                else:
                    drive_service.files().delete(fileId=spreadsheetId).execute()           # Delete 'test spreadsheet'
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Google drive configuration successful.",
                        extra_tags="alert-success",
                    )
                    return HttpResponseRedirect(reverse('dashboard'))


def export_findings(request, tid):
    test = Test.objects.get(id=tid)
    engagement = Engagement.objects.get(id=test.engagement_id)
    product = Product.objects.get(id=engagement.product_id)
    SCOPES = ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/spreadsheets']
    system_settings=get_object_or_404(System_Settings, id=1)
    service_account_info = json.loads(system_settings.credentials)
    credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=SCOPES)
    drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)
    system_settings = get_object_or_404(System_Settings, id=1)
    folder_id = system_settings.drive_folder_ID
    spreadsheet_name = product.name + "-" + engagement.name + "-" + str(test.id)
    files = drive_service.files().list(q="mimeType='application/vnd.google-apps.spreadsheet' and parents in '%s' and name='%s'" %(folder_id, spreadsheet_name),
                                          spaces='drive',
                                          pageSize=10,
                                          fields='files(id, name)').execute()
    spreadsheets = files.get('files')
    if len(spreadsheets) > 0:
        spreadsheetId = spreadsheets[0].get('id')
        sync_findings(tid, spreadsheetId, credentials)
        messages.add_message(
            request,
            messages.SUCCESS,
            "Google sheet data synced with database",
            extra_tags="alert-success",
        )
    else:
        create_spreadsheet(tid, spreadsheet_name, credentials)
        messages.add_message(
            request,
            messages.SUCCESS,
            "Finding details successfully exported to google sheet",
            extra_tags="alert-success",
        )
    return HttpResponseRedirect(reverse('view_test', args=(tid, )))

def sync_findings(tid, spreadsheetId, credentials):
    print ('---------------------------------------syncing-----------------------------------')


def create_spreadsheet(tid, spreadsheet_name, credentials):
    print ('------------------------------------------Creating------------------------------------')
    sheets_service = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
    drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)
    #Create a new spreadsheet
    spreadsheet = {
    'properties': {
        'title': spreadsheet_name
        }
    }
    spreadsheet = sheets_service.spreadsheets().create(body=spreadsheet, fields='spreadsheetId').execute()
    spreadsheetId = spreadsheet.get('spreadsheetId')
    system_settings = get_object_or_404(System_Settings, id=1)
    folder_id = system_settings.drive_folder_ID
    #Move the spreadsheet inside the drive folder
    file = drive_service.files().get(fileId=spreadsheetId, fields='parents').execute()
    previous_parents = ",".join(file.get('parents'))
    file = drive_service.files().update(fileId=spreadsheetId,
                                        addParents=folder_id,
                                        removeParents=previous_parents,
                                        fields='id, parents').execute()
    #Update created spredsheet with finding details
    findings_list = get_findings_list(tid)
    result = sheets_service.spreadsheets().values().update(spreadsheetId=spreadsheetId,
                                                    range='Sheet1!A1',
                                                    valueInputOption='RAW',
                                                    body = {'values': findings_list}).execute()
    #Format the header raw
    body = {
      "requests": [
        {
          "repeatCell": {
            "range": {
              "sheetId": 0,
              "startRowIndex": 0,
              "endRowIndex": 1
            },
            "cell": {
              "userEnteredFormat": {
                "backgroundColor": {
                  "red": 0.0,
                  "green": 0.0,
                  "blue": 0.0
                },
                "horizontalAlignment" : "CENTER",
                "textFormat": {
                  "foregroundColor": {
                    "red": 1.0,
                    "green": 1.0,
                    "blue": 1.0
                  },
                  "fontSize": 12,
                  "bold": True
                }
              }
            },
            "fields": "userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)"
          }
        },
        {
          "updateSheetProperties": {
            "properties": {
              "sheetId": 0,
              "gridProperties": {
                "frozenRowCount": 1
              }
            },
            "fields": "gridProperties.frozenRowCount"
          }
        }
      ]
    }
    sheets_service.spreadsheets().batchUpdate(spreadsheetId=spreadsheetId, body=body).execute()
    #Format columns with input field widths
    field_widths=system_settings.column_widths.split(",")
    body = {}
    body["requests"]=[]
    for i in range (len(field_widths)):
        body["requests"].append({
            "updateDimensionProperties": {
                "range": {
                    "sheetId": 0,
                    "dimension": "COLUMNS",
                    "startIndex": i,
                    "endIndex": i+1
                },
                "properties": {
                    "pixelSize": int(field_widths[i])
                },
                "fields": "pixelSize"
            }
        })
    sheets_service.spreadsheets().batchUpdate(spreadsheetId=spreadsheetId, body=body).execute()


def get_findings_list(tid):
    test = Test.objects.get(id=tid)
    findings = Finding.objects.filter(test=test).order_by('numerical_severity')
    fields = Finding._meta.fields
    findings_list = []
    headings = []
    for i in fields:
        headings.append(i.name)
    findings_list.append(headings)
    for finding in findings:
        finding_details = []
        for i in headings:
            val=str(eval("finding." + i))
            finding_details.append(val)
        findings_list.append(finding_details)
    return findings_list
