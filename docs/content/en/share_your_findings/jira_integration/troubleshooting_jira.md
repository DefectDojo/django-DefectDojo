---
title: "Troubleshooting Jira errors"
description: "Set up a Jira Configuration in DefectDojo - step 1 of working with Jira"
---

Here are some common issues with the Jira integration, and ways to address them.

## Findings that I 'Push To Jira' do not appear in Jira
Using the 'Push To Jira' workflow triggers an asynchronous process, however an Issue should be created in Jira fairly quickly after 'Push To Jira' is triggered.

* Check your DefectDojo notifications to see if the process was successful.  If the push failed, you will get an error response from Jira in your notifications.

Common reasons issues are not created:
* The Default Issue Type you have selected is not usable with the Jira Project
* Issues in the Project have required attributes that prevent them from being created via DefectDojo (see our guide to [Custom Fields](../using_custom_fields/))


## Error: Product Misconfigured or no permissions in Jira?

This error message can appear when attempting to add a created Jira configuration to a Product.  DefectDojo will attempt to validate a connection to Jira, and if that connection fails, it will raise this error message.

* Check to see if your Jira credentials are allowed to create issues in the given Jira Project you have selected.
* The "Project Key" field needs to be a valid Jira Project. Jira issues can use many different Keys within a single Project; the easiest way to confirm your Project Key is to look at the URL for that particular Jira Project: generally this will look like `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  In this case `JTV` is the Project Key.

## Changes made to Jira issues are not updating Findings in DefectDojo

* Start by confirming that the [DefectDojo webhook receiver](../connect_to_jira/#configure-bidirectional-sync-jira-webhook) is configured correctly and can successfully receive updates.

* If you're trying to push status changes, confirm that Jira transition mappings are set up correctly (Reopen / Close [Transition IDs](../connect_to_jira/#configure-bidirectional-sync-jira-webhook)).