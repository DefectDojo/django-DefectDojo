---
title: "Troubleshooting Jira errors"
description: "Fixing issues with a Jira integration"
weight: 2
---

Here are some common issues with the Jira integration, and ways to address them.

## Unable to setup Jira configuration in DefectDojo due to 404, 401 or 403 errors
Jira Cloud:
- Consult the Jira Cloud REST API documentation on authentication: https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- Verify on the command line that the provided credentials can access the necessary issues in Jira:

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

For example:
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center or Server:
- Consult the Jira Data Center REST API documentation on authentication:
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (username + password)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (personal access token)
- Verify on the command line that the provided credentials can access the necessary issues in Jira:

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

For example:
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

When using personal access tokens:
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

For example:
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```


## Findings that I 'Push To Jira' do not appear in Jira
Using the 'Push To Jira' workflow triggers an asynchronous process, however an Issue should be created in Jira fairly quickly after 'Push To Jira' is triggered.

* Check your DefectDojo notifications to see if the process was successful.  If the push failed, you will get an error response from Jira in your notifications.

Common reasons issues are not created:
* The Default Issue Type you have selected is not usable with the Jira Project
* Issues in the Project have required attributes that prevent them from being created via DefectDojo (see our guide to [Custom Fields](../jira_guide/#custom-fields-in-jira))


## Error: Product Misconfigured or no permissions in Jira?

This error message can appear when attempting to add a created Jira configuration to a Product.  DefectDojo will attempt to validate a connection to Jira, and if that connection fails, it will raise this error message.

* Check to see if your Jira credentials are allowed to create issues in the given Jira Project you have selected.
* The "Project Key" field needs to be a valid Jira Project. Jira issues can use many different Keys within a single Project; the easiest way to confirm your Project Key is to look at the URL for that particular Jira Project: generally this will look like `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  In this case `JTV` is the Project Key.

## Changes made to Jira issues are not updating Findings in DefectDojo

* Start by confirming that the [DefectDojo webhook receiver](../jira_guide/#step-3-configure-bidirectional-sync-jira-webhook) is configured correctly and can successfully receive updates.

* Ensure the SSL certificate used by Defect Dojo is trusted by JIRA. For JIRA Cloud you must use [a valid SSL/TLS certificate, signed by a globally trusted certificate authority](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* If you're trying to push status changes, confirm that Jira transition mappings are set up correctly (Reopen / Close [Transition IDs](../jira_guide/#step-3-configure-bidirectional-sync-jira-webhook)).

* [Test](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) your JIRA webhook using a public endpoint such as Pipedream or Beeceptor:

## Jira Epics aren't being created

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

DefectDojo's Jira integration needs a customfield value for 'Epic Name'.  However, your Project settings might not actually use 'Epic Name' as a field when creating Epics.  Atlassian made a change in [August 2023](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) which combined the 'Epic Name' and 'Epic Summary' fields.

Newer Jira Projects might not use this field when creating Epics by default, which results in this error message.

To correct this issue, you can add the 'Epic Name' field to your Project's issue creation screen:

1. Attempt to create an Epic in Jira manually (through Jira UI).
2. Open the "..." menu
3. Click 'Find Your Field'
4. Type in 'Epic Name'
5. Add Epic Name as a field to this particular screen by following Jira's instructions.

![image](images/epic_name_error.png)