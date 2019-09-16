import logging

import ast
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from dojo.models import System_Settings

logger = logging.getLogger(__name__)

def connect_to_google_apis(request):
    system_settings=get_object_or_404(System_Settings, id=1)
    credentials = system_settings.credentials
    # if 'credentials' not in request.session:
    #     return redirect('drive_authentication')
    if not credentials:
        return redirect('drive_authentication')
    cred = ast.literal_eval(credentials)
    credentials = google.oauth2.credentials.Credentials(cred)
    drive = googleapiclient.discovery.build('drive', 'v3', credentials=credentials)
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
        prompt='select_account',
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
