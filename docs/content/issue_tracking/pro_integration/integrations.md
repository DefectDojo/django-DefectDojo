---
title: "Pro Integrations"
weight: 1
audience: pro
aliases:
  - /en/share_your_findings/integrations
---
DefectDojo Pro's Integrations let you push your Findings and Finding Groups to ticket tracking systems to easily integrate security remediation with your teams existing development workflow.

Supported Integrations:
- [Azure Devops](/issue_tracking/pro_integration/integrations/#azure-devops-boards)
- [GitHub](/issue_tracking/pro_integration/integrations/#github)
- [GitLab Boards](/issue_tracking/pro_integration/integrations/#gitlab)
- [ServiceNow](/issue_tracking/pro_integration/integrations/#servicenow)

## Opening the Integrations page

The Integrations page can be found under **Settings > Integrations** in the sidebar.

![image](images/integrators_3.png)

## Setting up an Integration

An Integrator is configured with three key components:

- **Integration Instance**: This is the primary connection method that DefectDojo will use with a third-party system.  The Instance will include details such as a label, location and credentials to connect with, along with any other information that may be required by the vendor.
- **Issue Tracker Mapping**: This is where mapping information is stored - defining the details required to connect to a given "project" within the vendor.  These details include the name or ID of the "project", and mappings from DefectDojo Finding severity and status to the corresponding field in the vendor "ticket".  You may have multiple mappings configured if you are trying to push Findings to multiple "project" locations.
- **Issue Tracker Assignment**: This is where DefectDojo Products and Engagements are assigned to a given Issue Tracker Mapping, with per-Product/Engagement options to to define how a Finding will be pushed to a given vendor system.

These components are hierarchical: Each **Instance** has one or more **Mappings**, which then have one or more **Tracker Assignments**.

![image](images/integrators_2.png)

## Pushing Findings and Finding Groups

Once these components are configured, Findings and Finding Groups can be sent to a given Issue Tracker in two ways; manually, or automatically.

- **Manually**: Findings and Finding Groups contained in a Product/Engagement with an assigned **Issue Tracker Mapping** will have an option to "Push to Integrators".  This will then create an Issue in the Issue Tracker with the corresponding Finding/Finding Group information.  Push To Integrators can also be used to update an existing Issue.

### Automatically Push Findings

Findings can also be pushed automatically, with the **Issue Tracker Assignment** dictating how those objects will be pushed.  These are the four options:

- **Explicitly Publish Changes**: This option disables any automatic behavior in the assigned Product or Engagement.  The only way to push a Finding or Finding Group will be explicitly, as mentioned above.
- **Automatically Link New Findings**: When new Findings or Finding Groups are **created** in the assigned Product or Engagement, DefectDojo will automatically push the object to the Issue Tracker.  Once created, these Findings or Findings Groups will not be updated without a manual Push To Integrators action.
- **Automatically Update Existing Link**: When Findings or Finding Groups are **updated** in the assigned Product or Engagement, automatically push the object to the Issue Tracker if an existing link has already been created manually.
- **Automatically Link New and Update Existing Link**: When Findings or Finding Groups are created **or** updated in the assigned Product or Engagement, automatically push the object to the Issue Tracker.

## Issue Tracker Ticket Representation

Issue Tracker Tickets are represented by a series of icons under the "Integrator Tickets" column when viewing and listing
Findings and Finding Groups

Icons from left to right:

- **Integration Type**: The type of Issue Tracker the Ticket is associated with
- **Ticket ID**: The ID of the Ticket, as defined by the Issue Tracker
- **Ticket Link**: The direct link to the Ticket, as define by the Issue Tracker
- **Changelog**: Specifies when the Issue Tracker Ticket was associated with a Finding or Finding Group, as well as the last time DefectDojo made a change to the ticket

![image](images/integrators_1.png)

## Supported Project Integrations

Project Integrations will have varying requirements for how DefectDojo will need to interact with them. This could be in the form of an authentication mechanism, additional fields on a per "project" basis, or severity/status mappings.

For the complete list of requirements, please open the vendor specific pages below:

- [Azure Devops](/issue_tracking/pro_integration/integrations/#azure-devops-boards)
- [GitHub](/issue_tracking/pro_integration/integrations/#github)
- [GitLab Boards](/issue_tracking/pro_integration/integrations/#gitlab)
- ServiceNow (Coming Soon)

## Error Handling and Debugging

Integrations can produce errors for a variety of reasons such as connectivity, authentication, permissions, etc.. To assist
in debugging these errors, each Issue Tracker Mapping has a table of errors that list when the error occurred, the reason it
occurred, and the Finding or Finding Group that failed to be pushed.

These errors can be found by looking at the Issue Tracker Mappings & Assignments page, under the ⚠️ Total Errors column.

![image](images/integrators_4.png)

Clicking on the Total Errors entry will bring you to a page with more detailed descriptions of errors associated with this Integration.
