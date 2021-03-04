---
title: "JIRA Integration"
date: 2021-02-02T20:46:28+01:00
draft: false
---

DefectDojo\'s JIRA integration is bidirectional. You may push findings
to JIRA and share comments. If an issue is closed in JIRA it will
automatically be closed in Dojo.

**NOTE:** These steps will configure the necessary webhook in JIRA and add JIRA integration into DefectDojo. This isn\'t sufficient by itself, you will need to configure products and findings to push to JIRA. On a product\'s settings page you will need to define a:

:   -   Project Key (and this project must exist in JIRA)
    -   JIRA Configuration (select the JIRA configuration that you
        create in the steps below)
    -   Component (can be left blank)

Then elect (via tickbox) whether you want to \'Push all issues\',
\'Enable engagement epic mapping\' and/or \'Push notes\'. Then click on
\'Submit\'.

If creating a Finding, ensure to tick \'Push to jira\' if desired.

Enabling the Webhook
....................

:   1.  Visit <https://>\<**YOUR JIRA URL**\>/plugins/servlet/webhooks
    2.  Click \'Create a Webhook\'
    3.  For the field labeled \'URL\' enter: <https://>\<**YOUR DOJO
        DOMAIN**\>/webhook/
    4.  Under \'Comments\' enable \'Created\'. Under Issue enable
        \'Updated\'.

Configurations in Dojo
......................

:   1.  Navigate to the System Settings from the menu on the left side
        or by directly visiting \<your url\>/system\_settings.
    2.  Enable \'Enable JIRA integration\' and click submit.

Adding JIRA to Dojo
...................

:   1.  Click \'JIRA\' from the left hand menu.
    2.  Select \'Add Configuration\' from the drop-down.
    3.  If you use Jira Cloud, you will need to generate an [API token
        for Jira](https://id.atlassian.com/manage/api-tokens) to use as
        the password
    4.  To obtain the \'open status key\' and \'closed status key\'
        visit <https://>\<**YOUR JIRA
        URL**\>/rest/api/latest/issue/\<**ANY VALID ISSUE
        KEY**\>/transitions?expand=transitions.fields
    5.  The \'id\' for \'Todo\' should be filled in as the \'open status
        key\'
    6.  The \'id\' for \'Done\' should be filled in as the \'closed
        status key\'

    To obtain \'epic name id\': If you have admin access to JIRA:

    1.  visit: <https://>\<**YOUR JIRA
        URL**\>/secure/admin/ViewCustomFields.jspa
    2.  Click on the cog next to \'Epic Name\' and select view.
    3.  The numeric value for \'epic name id\' will be displayed in the
        URL
    4.  **Note**: dojojira uses the same celery functionality as
        reports. Make sure the celery runner is setup correctly as
        described:
        <https://defectdojo.github.io/django-DefectDojo/basics/features/#reports>

    Or

    1.  login to JIRA
    2.  visit <https://yourjiraurl/rest/api/2/field> and use control+F
        or grep to search for \'Epic Name\' it should look something
        like this:

    {\"id\":\"customfield\_122\",\"key\":\"customfield\_122\",\"name\":\"Epic
    Name\",\"custom\":true,\"orderable\":true,\"navigable\":true,\"searchable\":true,\"clauseNames\":\[\"cf\[122\]\",\"Epic
    Name\"\],\"schema\":{\"type\":\"string\",\"custom\":\"com.pyxis.greenhopper.jira:gh-epic-label\",\"customId\":122}},

    **In the above example 122 is the number needed**

**Customize JIRA issue description**

By default Defect Dojo uses the `dojo/templates/issue-trackers/jira-description.tpl` template to render the description of the 'to be' created JIRA issue.
This file can be modified to your needs, rebuild all containers afterwards. There's also a more limited template available, which can be chosen when
configuring a JIRA Instance or JIRA Project for a Product or Engagement:

![image](../../images/jira_issue_templates.png)

Any template add to  `dojo/templates/issue-trackers/` will be added to the dropdown (after rebuilding/restarting the containers).

Engagement Epic Mapping
.......................

If creating an Engagement, ensure to tick 'Enable engagement epic mapping' if desired. This can also be done after engagement creation on the edit engagement page.
This will create an 'Epic' type issue within Jira. All findings in the engagement pushed to Jira will have a link to this Epic issue.
If Epic Mapping was enabled after associated findings have already been pushed to Jira, simply pushing them again will link the Jira issue to the Epic issue.

Pushing findings
................

Findings can be pushed to Jira in a number of ways:

1. When importing scanner reports, select 'Push to JIRA' to push every single finding in the report to Jira
2. When creating a new finding, select 'Push to JIRA' and submit. This will create the finding in DefectDojo and Jira simultaneously
3. If a finding already exist, visit the edit finding page and find the 'Push to JIRA' tick box at the bottom
4. When viewing a list of findings, select each relevant tick boxes to the left of the finding, and click the 'Bulk Edit' button at the top. find 'Push to JIRA' at the bottom of the menu

**Known Issues**

DefectDojo will try to keep the status in sync with the status in JIRA
using the various status IDs configured for each JIRA instance. This
will only work if your workflow in JIRA allows arbitrary transitions
between the statuses JIRA issues can be in. The Risk Acceptance feature
in DefectDojo will (for that reason) not (yet) try to sync statuses. A
comment will be pushed to JIRA if a finding is risk accepted or
unaccepted. Contributions are welcome to enhance the integration.

**Troubleshooting JIRA integration**

JIRA actions are typically performed in the celery background process.
Errors are logged as alerts/notifications to be seen on the top right of
the DefectDojo UI and in stdout of the celery workers.
