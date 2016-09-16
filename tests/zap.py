#!/usr/bin/python
import time
import os
import subprocess
import urllib
from pprint import pprint
from zapv2 import ZAPv2
#from user_input import *
from urlparse import urlparse
#from get_params import *

class Main:
    if __name__ == "__main__":

        print ("Checking if ZAP is running.")
        #ps=subprocess.Popen(['ps','-afe'],stdout=subprocess.PIPE)
        #grep=subprocess.Popen(['grep','[z]ap'],stdin=ps.stdout,stdout=subprocess.PIPE)
        #x=grep.communicate()

        zap = ZAPv2() #Creating zap api version2 object
        apikey = "an6f4pt7d3mvql8th0o67bt0mo" #Plan is to set new api key everytime using -config api.key=change-me-9203935709 using random() function. Until then will use static keys.
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'})

        #user_input_obj = User_Input() #Creating object for class User_Input
        #targetURL,sessionmethod,authmethod = user_input_obj.user_input()
        #print ("Returning from user input: " + targetURL,sessionmethod)
        targetURL="http://wwww.cengage.com"
        targetURLregex = "\Q"+targetURL+"\E.*" #Regular expression to be considered within our context.

        #Defining context name as hostname from URL and creating context using it.
        contextname = urlparse(targetURL).netloc
        print ("Context Name: " + contextname)

        # Step1: Create context
        contextid = zap.context.new_context(contextname,apikey)
        print ("ContextID: "+contextid)

        #Step2: Include in the context
        result = zap.context.include_in_context(contextname,targetURLregex,apikey)
        print ("URL regex defined in context: " + result)

        #Step3: Session Management - Default is cookieBasedSessionManagement
        result = zap.sessionManagement.set_session_management_method(contextid,sessionmethod,None,apikey)
        print ("Session method defined: "+ result)

        #Step4: Configure and set Authentication Method
        loginUrl = urllib.quote_plus(raw_input("loginURL="))
        loginRequestData = urllib.quote_plus("username={%username%}&password={%password%}")
        config_params = "loginUrl=" + loginUrl + "&loginRequestData=" + loginRequestData    #{"methodConfigParams":[{"name":"loginUrl","mandatory":"true"},{"name":"loginRequestData","mandatory":"false"}]}
        result = zap.authentication.set_authentication_method(contextid,authmethod,config_params,apikey)
        print ("Authentication method defined: "+ result)

        #Step5: Set log in indicator
        loggedInIndicator = '\Qlogout\E'
        result = zap.authentication.set_logged_in_indicator(contextid,loggedInIndicator,apikey)
        print ("Login Indicator defined: " + result)

        #Step6: Create new user
        userId = zap.users.new_user(contextid,"user",apikey)
        print ("New user created. UserID: " + userId)

        #Step7: Add user credentials
        params_obj = Get_Params()
        params = params_obj.get_user_login_parameters()
        print ("Login Parameters: " +params)
        result = zap.users.set_authentication_credentials(contextid,userId,params,apikey)
        print ("Adding user credentials: " + result)

        #Step8: Enable user
        result = zap.users.set_user_enabled(contextid,userId,True,apikey)
        print ("Enabling user: "+ result)

        #Step9: Spider URL as user
        spiderId = zap.spider.scan_as_user(contextid,userId,targetURL,5,None,None,apikey)
        print ("Crawling through")

        #Step10: Scan.
        # Wait for spider to complete.
        while int(zap.spider.status(spiderId)) < 100:
            print ("Waiting 10 seconds for spider to complete crawling through the website...")
            time.sleep(10)

        # Wait for passive scanning to complete
        while (int(zap.pscan.records_to_scan) > 0):
          print ('Records to passive scan : ' + zap.pscan.records_to_scan)
          time.sleep(2)
        print ('Passive scanning complete')

        print ('Actively Scanning target ' + targetURL)
        ascan_id = zap.ascan.scan(targetURL,None,None,None,None,None,apikey) #Can provide more options for active scan here instead of using None.
        while (int(zap.ascan.status(ascan_id)) < 100):
            print ('Scan progress %: ' + zap.ascan.status(ascan_id))
            time.sleep(5)

        print ('Scan completed')

        # Report the results
        print ('Hosts: ' + ', '.join(zap.core.hosts))
        print ('Sites: ' + ', '.join(zap.core.sites))
        print ('Urls: ' + ', '.join(zap.core.urls))
        print ('Alerts: ')
        pprint (zap.core.alerts())

        #Step11: Generate XML/HTML report
        f_html=open("/Users/vgori/OneDriveBusiness/CengageLearning/AppSec/ZAP/reports/report.html",'w')
        f_html.write(zap.core.htmlreport(apikey))
        #report = zap.core.xmlreport(apikey)


        '''
        ToDo:
        1. Check if authentication was successful at various levels. Including spider and active scan.
        2. Spider for login URL. Once found use it as loginURL parameter for authentication.
        '''
