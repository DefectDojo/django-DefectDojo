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


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962203362/711708ba18887c909eb7e315/9UD98h1gZT6IlhmTeHCFrypNcbJnRjqXLvrL4YOShDvR5DPTrr1sG8ohEkWS8d0NSPs2-Kz7jRM3CKvMfmO3CVx6V8OpiT98V75L8IyEA5iq4m1YIZmiBSsYshvuFZYcppzueBz3pA7A_5q_BuQSj2A?expires=1729720800&signature=d0240c843f37d66039cb98dd73ebee04e450002e9e31644517a207a0c54c7565&req=fSYlFMl9noddFb4f3HP0gNqGPNxDYkTTpt0uyAWrCi5EKyiDsGePVH3rfF2a%0AjNo%3D%0A)
2. Open the SAML tab from this page to configure your sign\-on settings.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962203371/122013c5bd92a17058bffcc9/WxdWys-zS52WnnWj8hN_MSd181XqoLt0ovx28_1TxiXGngclO0rZx3rHM1d6NBvbAuZLzT9YNjsrIPhlJx7UOOLkftWL2fcUzFwKzEzHxzhp30cqaECI-XTwiTekk7UNCofh7xyDyMJ4E7-MjqhEApM?expires=1729720800&signature=8783a41b09e02104c10c696be712ce843d80406da16acc9091b843057d41bb50&req=fSYlFMl9noZeFb4f3HP0gOOiXRyUrpec5LNNWeTj47Yz9rMjGNIySCYTH1xh%0AiKE%3D%0A)
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


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962203378/5569f32d153fb51d9a725e54/OCJmjuI1gLuEbNaMjpore21_xlbVFZCfcChthYdnXjkDE1W_-HyfSTDbJfASHNZX0myFYWWL0eqV0oyQ-4gOBJrSCtwn47SXDli8dPopFNZb34k9i4T2GfPfkhPi1-1J-X9-Op0EVIRvx41BPx3w0Yw?expires=1729720800&signature=512df502470da5028b0e41bfb4e1b3671260b9292f5e49ec1bc72298259fb602&req=fSYlFMl9noZXFb4f3HP0gDNvSgyDTmnMnfcjRvKa660M%2BhNfabgrDzvgB6QV%0AiX4%3D%0A)

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


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962203384/0f0a7284a08e975fc6d274ad/9UD98h1gZT6IlhmTeHCFrypNcbJnRjqXLvrL4YOShDvR5DPTrr1sG8ohEkWS8d0NSPs2-Kz7jRM3CKvMfmO3CVx6V8OpiT98V75L8IyEA5iq4m1YIZmiBSsYshvuFZYcppzueBz3pA7A_5q_BuQSj2A?expires=1729720800&signature=ebc69ccc466b50855ef4e021678302c910e5122b1efe85a4f3177125c13d4818&req=fSYlFMl9nolbFb4f3HP0gDJIgX6Exhy5n7%2FXJaBEZZbyHTcVfeAqpDsS9WA7%0AgI8%3D%0A)
2. From here, navigate to the OAuth tab and select the service you want to configure from the list.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962203390/feb13027b266b7f1a56c3c6a/lyWcUB9Jyf5ZQzDXvjrX830ShYi0AduEa7UJmtmZhabeNpjLhbHGNlcDtEXj6H44KFGJMmpE-ym55m-T5jvPDHoWabIMjo5hoRgOsr2fJk5EpCMyzmZ2fSE-JWMgIfDz8g6fTB2vuFQf703pcQILAgY?expires=1729720800&signature=bc4fb3d86492eaba3420063f792926ab3aaa884a36a988ad1cdd6ae6aae3d74e&req=fSYlFMl9nohfFb4f3HP0gM6xKW5NsJPRtLYFcZOwplcZ%2Bfx5dKJvKR%2BMjmNV%0AoOE%3D%0A)
3. Complete the relevant OAuth form.  
​
4. Finally, check the **Enable \_\_ OAuth** button from below, and click **Submit**.   
​

Users should now be able to sign in using the OAuth service you selected. A button will be added to the DefectDojo Login page to enable them to sign on using this method.


