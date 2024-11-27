---
title: "Configure Single-Sign On Login"
description: "Sign in to DefectDojo using OAuth or SAML login options"
pro-feature: true
---

Users can connect to DefectDojo with a Username and Password, but if you prefer, you can allow users to authenticate using a Single Sign\-On or SSO method. You can set up DefectDojo to work with your own SAML Identity Provider, but we also support many OAuth methods for authentication:


* Auth0
* Azure AD
* GitHub Enterprise
* GitLab
* Google
* KeyCloak
* Okta

All of these methods can only be configured by a Superuser in DefectDojo.  
​



# Set Up SAML Login


If you would like to add DefectDojo to your SAML Identity Provider, here is the process to follow:


1. Start from **Plugin Manager \> Enterprise Settings** in DefectDojo.  
​


![image](images/Configure_Single-Sign_On_Login.png)
2. Open the SAML tab from this page to configure your sign\-on settings.  
​


![image](images/Configure_Single-Sign_On_Login_2.png)
3. Complete the SAML form. Start by setting an **Entity ID** \- this is either a label or a URL which your SAML Identity Provider can point to, and use to identify DefectDojo. This is a required field.  
​
4. If you wish, set **Login Button Text** in DefectDojo. This text will appear on the button or link users click to initiate the login process.  
​
5. You can also set a **Logout URL** to redirect your users to once they have logged out of DefectDojo.  
​
6. The **NameID Format** has four options \- Persistent, Transient, Entity and Encrypted.  
​   
\- If you want your users to be consistently identified by SAML, use **Persistent.**   
\- If you would prefer that users have a different SAML ID each time they access   
DefectDojo, choose **Transient**.   
\- If you’re ok with all of your users sharing a SAML NameID, you can select **Entity.**   
\- If you would like to encrypt each user’s NameID, you can use **Encrypted** as your NameID format.  
​
7. **Required Attributes** are the attributes that DefectDojo requires from the SAML response.  
​
8. **Attribute Mapping** contains a formula for how you want these attributes to be matched to a user. For example, if your SAML response returns an email, you can associate it with a DefectDojo user with the formula **email\=email**.  
​  
The left side of the ‘\=’ sign represents the attribute you want to map from the SAML response. The right side is a user’s field in DefectDojo, which you want this attribute to map to.  
​  
This is a required field for this form.  
​
9. **Remote SAML Metadata** is the URL where your SAML Identity Provider is located.  
​
10. If you would prefer to upload your own SAML Metadata, you can upload an XML file to **Local SAML Metadata**. You will need at least one metadata source before you can successfully use SAML.  
​
11. Finally, check the **Enable SAML** checkbox at the bottom of this form to confirm that you want to use SAML to log in. Once this is enabled, you will see the **Login With SAML** button on the DefectDojo Login Page.


![image](images/Configure_Single-Sign_On_Login_3.png)

## Additional SAML Options:


**Create Unknown User** allows you to decide whether or not to automatically create a new user in DefectDojo if they aren’t found in the SAML response.



**Allow Unknown Attributes** allows you to authorize users who have attributes which are not found in the **Attribute Mapping** field.



**Sign Assertions/Responses** will require any incoming SAML responses to be signed.



**Sign Logout Requests** forces DefectDojo to sign any logout requests.



**Force Authentication** determines whether you want to force your users to authenticate using your Identity Provider each time, regardless of existing sessions.



**Enable SAML Debugging** will log more detailed SAML output for debugging purposes.





# Set up OAuth Login (Google, Gitlab, Auth0…)


1. Start by navigating to the **Plugin Manager \> Enterprise Settings** page in DefectDojo.  
​


![image](images/Configure_Single-Sign_On_Login_4.png)
2. From here, navigate to the OAuth tab and select the service you want to configure from the list.  
​


![image](images/Configure_Single-Sign_On_Login_5.png)
3. Complete the relevant OAuth form.  
​
4. Finally, check the **Enable \_\_ OAuth** button from below, and click **Submit**.   
​

Users should now be able to sign in using the OAuth service you selected. A button will be added to the DefectDojo Login page to enable them to sign on using this method.


