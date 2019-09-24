import logging

import ast
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from dojo.models import System_Settings, Finding
from dojo.forms import GoogleSheetFieldsForm
from dojo.utils import add_breadcrumb
# from django.core.files.storage import FileSystemStorage

logger = logging.getLogger(__name__)

def connect_to_google_apis(request):
    system_settings=get_object_or_404(System_Settings, id=1)
    credentials = system_settings.credentials
    # if 'credentials' not in request.session:
    #     return redirect('drive_authentication')
    if not credentials:
        return redirect('drive_authentication')
    cred = ast.literal_eval(credentials)
    credentials = google.oauth2.credentials.Credentials(
            token=cred['token'],
            refresh_token=cred['refresh_token'],
            token_uri=cred['token_uri'],
            client_id=cred['client_id'],
            client_secret=cred['client_secret'],
            scopes=cred['scopes'])
    drive = googleapiclient.discovery.build('sheets', 'v4', credentials=credentials)
    result = drive.spreadsheets().values().get(spreadsheetId='11vqUtAuweSy1d8L-Zwb6Un-vig86Rn6RLMqTAnWp5Ko', range='A2:E2').execute()
    rows = result.get('values', [])
    print('{0} rows retrieved.'.format(len(rows)))
    # request.session['credentials'] = credentials_to_dict(credentials)
    return render(request, 'dojo/testing.html', {
        'name': 'Connect to drive',
    })


@user_passes_test(lambda u: u.is_superuser)
def drive_authentication(request):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        '/app/dojo/google_sheet/client_secret.json',
        scopes=['https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/spreadsheets'])
    flow.redirect_uri = 'http://localhost:8080/oauth2callback'
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true')
    request.session['state'] = state
    return HttpResponseRedirect(authorization_url)

@user_passes_test(lambda u: u.is_superuser)
def oauth2callback(request):
    state = request.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        '/app/dojo/google_sheet/client_secret.json',
        scopes=['https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/spreadsheets'], state=state)
    flow.redirect_uri = 'http://localhost:8080/oauth2callback'
    data = request.GET
    code = data.get('code')
    flow.fetch_token(code=code)
    credentials = flow.credentials
    system_settings=get_object_or_404(System_Settings, id=1)
    system_settings.credentials=str(credentials_to_dict(credentials))
    system_settings.save()
    # request.session['credentials'] = credentials_to_dict(credentials)
    return redirect ('connect_to_google_apis')

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


def google_sheet_config(request):
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
            system_settings.save()

            #Save uploaded json file
            cred_file = request.FILES['cred_file']
            # fs = FileSystemStorage()
            # filename = fs.save(cred_file.name, cred_file)
            #request.session['credentials'] = cred_file


    add_breadcrumb(title="Google Sheet Configuration", top_level=False, request=request)
    return render(request, 'dojo/google_sheet_configuration.html', {
        'name': 'Google Sheet Configuration',
        'metric': False,
        'form':form,
    })
