---
title: "Using the Cloud Manager"
description: "Manage your subscription and account settings"
weight: 1
---

Logging into DefectDojo's Cloud Manager allows you to configure your account settings and manage your subscription with DefectDojo Cloud.

## **New Subscription**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

This page allows you to request a [new, or additional Cloud instance](../set-up-an-additional-cloud-instance) from DefectDojo. 

## **Manage Subscriptions**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

The Subscription Management page shows all of your currently active Cloud instances, and allows you to configure the Firewall settings for each instance.

### Changing your Firewall Settings
![image](images/using_the_cloud_manager.png)

Once on the **Edit Subscription** page, enter the IP Address, Mask, and Label for the rule you wish to add. If more than one firewall rule is needed, click **Add New Range** to create a new empty rule.

![image](images/using_the_cloud_manager_2.png)

Here, you can also open your firewall to external services (GitHub & Jira Cloud).  You can also disable your firewall entirely, if you wish, by selecting **Proceed Without Firewall** from the menu.

## Adding additional users to the Cloud Portal

If you have multiple users who you want to give control over your Cloud Portal / DefectDojo Subscription, you can add them using this form.  The users you want to add will have to have created their own Cloud Portal account at cloud.defectdojo.com; having an account on your DefectDojo instance is not sufficient.

![image](images/using_the_cloud_manager_5.png)

Enter the email associated with the user's Cloud Portal account, and click Submit to add them to your list of linked users.  The user will now be able to manage the Cloud Portal and your DefectDojo subscription.

## Resources
<https://cloud.defectdojo.com/resources/>

The Resources page contains a Contact Us form, which you can use to get in touch with our Support team.

![image](images/using_the_cloud_manager_3.png)

## Tools
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

The Tools page is one of the places where you can download external Pro tools, such as Universal Importer or DefectDojo CLI.  These tools are external add-ons which can be used to quickly build a command-line import pipeline in your network. For more information about these tools, see the [External Tools](../../connecting_your_tools/external_tools/) documentation.

![image](images/using_the_cloud_manager_6.png)


## Account Settings
<https://cloud.defectdojo.com/accounts/settings>

The account settings page has four sections:

* **User Contact** allows you to set your Username, Email Address, First Name and Last Name.
* **Email Accounts** allows you to add additional email addresses to your accounts. Adding an additional email account will send a verification email to the new address.
* **Manage Social Accounts** allows you to connect DefectDojo Cloud to your GitHub or Google credentials, which can be used to log in instead of a username and password.
* **MFA Settings** allow you to add an MFA code to Google Authenticator, 1Password or similar apps. Adding an additional step to your login process is a good proactive step to prevent unauthorized access.

### Add MFA to your Cloud Portal login
<https://cloud.defectdojo.com/settings/mfa/configure/>

Note that this will only add MFA to your DefectDojo Cloud login, not to the login for your DefectDojo app.

![image](images/using_the_cloud_manager_4.png)

1. Begin by installing an Authenticator app which supports QR code authentication on your smartphone or computer.
2. Once you've done this, click **Generate QR Code**.
3. Scan the QR code provided in DefectDojo using your Authenticator app, and then enter the six\-digit code provided by your app.
4. Click **Enable Multi\-Factor Authentication**.