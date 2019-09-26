import json
import googleapiclient.discovery
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
    # drive_service.permissions().create(body={'type':'user', 'role':'writer', 'emailAddress': 'lakmalip@wso2.com'}, fileId=spreadsheetId).execute()
    drive_service.files().delete(fileId=spreadsheetId).execute()                       # Delete 'test spreadsheet'
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
    # sheets_service = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
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
    else:
        create_spreadsheet(tid, spreadsheet_name, credentials)
    return HttpResponseRedirect(reverse('view_test', args=(tid, )))

def sync_findings(tid, spreadsheetId, credentials):
    sheets_service = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
    drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)

    print ('syncing')


def create_spreadsheet(tid, spreadsheet_name, credentials):
    sheets_service = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
    drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)
    findings_list = get_findings_list(tid)
    spreadsheet = {
    'properties': {
        'title': spreadsheet_name
        }
    }
    spreadsheet = sheets_service.spreadsheets().create(body=spreadsheet, fields='spreadsheetId').execute()
    spreadsheetId = spreadsheet.get('spreadsheetId')
    system_settings = get_object_or_404(System_Settings, id=1)
    folder_id = system_settings.drive_folder_ID
    file = drive_service.files().get(fileId=spreadsheetId, fields='parents').execute() # Retrieve the existing parents to remove
    previous_parents = ",".join(file.get('parents'))
    file = drive_service.files().update(fileId=spreadsheetId,                          # Move the file to the new folder
                                        addParents=folder_id,
                                        removeParents=previous_parents,
                                        fields='id, parents').execute()
    result = sheets_service.spreadsheets().values().update(spreadsheetId=spreadsheetId,
                                                    range='Sheet1!A1',
                                                    valueInputOption='RAW',
                                                    body = {'values': findings_list}).execute()
    requests = {
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
    sheets_service.spreadsheets().batchUpdate(spreadsheetId=spreadsheetId, body=requests).execute()

def get_findings_list(tid):
    test = Test.objects.get(id=tid)
    findings = Finding.objects.filter(test=test).order_by('numerical_severity')
    findings_list = []
    headings = ['id', 'title', 'date', 'cwe', 'cve', 'url', 'severity', 'description', 'mitigation', 'impact', 'steps_to_reproduce',
    'severity_justification', 'references', 'test', 'is_template', 'active', 'verified', 'false_p', 'duplicate', 'duplicate_finding',
    'out_of_scope', 'under_review', 'review_requested_by', 'under_defect_review', 'defect_review_requested_by', 'is_Mitigated',
    'thread_id', 'mitigated', 'mitigated_by', 'reporter', 'numerical_severity', 'last_reviewed', 'last_reviewed_by', 'line_number',
    'sourcefilepath', 'sourcefile', 'param', 'payload', 'hash_code', 'line', 'file_path', 'static_finding', 'dynamic_finding',
    'created', 'jira_creation', 'jira_change', 'scanner_confidence']
    findings_list.append(headings)
    for finding in findings:
        finding_details = [finding.id, finding.title, str(finding.date), finding.cwe, finding.cve, finding.url, finding.severity,
                finding.description, finding.mitigation, finding.impact, finding.steps_to_reproduce, finding.severity_justification,
                finding.references, str(finding.test), finding.is_template, finding.active, finding.verified, finding.false_p,
                finding.duplicate, finding.duplicate_finding, finding.out_of_scope, finding.under_review, str(finding.review_requested_by),
                finding.under_defect_review, str(finding.defect_review_requested_by), finding.is_Mitigated, finding.thread_id, finding.mitigated,
                str(finding.mitigated_by), str(finding.reporter)]
        findings_list.append(finding_details)
    return findings_list
