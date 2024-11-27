---
title: "Using Custom Fields in Jira"
description: "Making sure DefectDojo can successfully create Issues with custom fields"
---


**DefectDojo does not currently support passing any Issue\-specific information into these Custom Fields \- these fields will need to be updated manually in Jira after the issue is created. Each Custom Field will only be created from DefectDojo with a default value.**



**Jira Cloud now allows you to create a default Custom Field value directly in\-app. [See Atlassian's documentation on Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) for more information on how to configure this.** 



DefectDojo's built\-in Jira Issue Types (**Bug, Task, Story** and **Epic)** are set up to work 'out of the box'. Data fields in DefectDojo will automatically map to the corresponding fields in Jira. By default, DefectDojo will assign Priority, Labels and a Reporter to any new Issue it creates.



Some Jira configurations require additional custom fields to be accounted for before an issue can be created. This process will allow you to account for these custom fields in your DefectDojo \-\> Jira integration, ensuring that issues are created successfully. These custom fields will be added to any API calls sent from DefectDojo to a linked Jira instance.



If you don’t already use Custom Fields in Jira, there is no need to follow this process.




# Process Summary


1. Recording the names of your Custom Fields in Jira (**Jira UI**)
2. Determine the Key values for the new Custom Fields (Jira Field Spec Endpoint)
3. Locate the acceptable data for each Custom Field, using the Key values as a reference (Jira Issue Endpoint)
4. Create a Field Reference JSON block to track all of the Custom Field Keys and acceptable data (Jira Issue Endpoint)
5. Store the JSON block in the associated DefectDojo Product, to allow Custom Fields to be created from Jira (DefectDojo UI)
6. Test your work and ensure that all required data is flowing from Jira properly



## Step 1: Record the names of your Custom Fields in Jira


Jira supports a variety of different Context Fields, including Date Pickers, Custom Labels, Radio Buttons. Each of these Context Fields will have a different Key value that can be found in the Jira API.



Write down the names of each required Custom Field, as you will need to search through the Jira API to find them in the next step.



**Example of a Custom Field list (your Custom Field names will be different):**


* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...




## Step 2: Finding your Jira Custom Field Key Values


Start this process by navigating to the Field Spec URL for your entire Jira instance.



Here is an example of a Field Spec URL:


[https://yourcompany\-example.atlassian.net/rest/api/2/field](https://yourcompany-example.atlassian.net/rest/api/2/field)



The API will return a long string of JSON, which should be formatted into readable text (using a code editor, browser extension or <https://jsonformatter.org/>).



The JSON returned from this URL will contain all of your Jira custom fields, most of which are irrelevant to DefectDojo and have values of `“Null”`. Each object in this API response corresponds to a different field in Jira. You will need to search for the objects that have `“name”` attributes which match the names of each Custom Field you created in the Jira UI, and then note the value of their “key” attribute.



![image](images/Using_Custom_Fields.png)



Once you’ve found the matching object in the JSON output, you can determine the “key” value \- in this case, it's `customfield_10050`.



Jira generates different key values for each Custom Field, but these key values do not change once created. If you create another Custom Field in the future, it will have a new key value.




**Expanding our Custom Field list:**


* “DefectDojo Custom URL Field” \= customfield\_10050
* “Another example of a Custom Field” \= customfield\_12345
* ...




## Step 3 \- Finding the Custom Fields on a Jira Issue


Locate an Issue in Jira that contains the Custom Fields which you recorded in Step 2\. Copy the Issue Key for the title (should look similar to “`EXAMPLE-123`”) and navigate to the following URL:



[https://yourcompany\-example.atlassian.net/rest/api/2/issue/EXAMPLE\-123](https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123)



This will return another string of JSON.



As before, API output will contain lots of `customfield_##` object parameters with `null` values \- these are custom fields that Jira adds by default, which aren’t relevant to this issue. It will also contain `customfield_##` values that match the Custom Field Key values that you found in the previous step. Unlike with the Field Spec output, you won’t see names identifying any of these custom fields, which is why you needed to record the key values in Step 2\.



![image](images/Using_Custom_Fields_2.png)
**Example:**  
We know that `customfield_10050` represents the DefectDojo Custom URL Field because we recorded it in Step 2\. We can now see that `customfield_10050` contains a value of `“https://google.com”` in the `EXAMPLE-123` issue.




## Step 4 \- Creating a JSON Field Reference from each Jira Custom Field Key


You’ll now need to take the value of each of the Custom Fields from your list and store them in a JSON object (to use as a reference). You can ignore any Custom Fields that don’t correspond to your list.



This JSON object will contain all of the default values for new Jira Issues. We recommend using names that are easy for your team to recognize as ‘default’ values that need to be changed: ‘`change-me.com`’, ‘`Change this paragraph.`’ etc.




**Example:**


From step 3, we now know that Jira expects a URL string for "`customfield_10050`”. We can use this to build our example JSON object.



Say we had also located a DefectDojo\-related short text field, which we identified as "`customfield_67890`”. We would look at this field in our second API output, look at the associated value, and reference the stored value in our example JSON object as well.  
​  
Your JSON object will start to look like this as you add more Custom Fields to it.




```
{  
	"customfield_10050": "https://change-me.com",  
	"customfield_67890": "This is the short text custom field."  
}
```

Repeat this process until all of the DefectDojo\-relevant custom fields from Jira have been added to your JSON Field Reference.



#### Data types \& Jira Syntax


Some fields, such as Date fields, may relate to multiple custom fields in Jira. If that is the case, you’ll need to add both fields to your JSON Field Reference.




```
  "customfield_10040": "1970-01-01",  
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```


Other fields, such as the Label field, may be tracked as a list of strings \- please make sure your JSON Field Reference uses a format that matches API output from Jira.




```
// a list of custom labels on a Jira object  
  "customfield_10042": [  
    "custom-label-one",  
    "this-is-default",  
    "change-me-please"  
  ],
```


Other custom fields may contain additional, contextual information that should be removed from the Field Reference. For example, the Custom Multichoice Field contains an extra block in the API output, which you’ll need to remove, as this block stores the current value of the field.


* you should remove the extra object from this field:



```
"customfield_10047": [  
    {  
      "value": "A"  
    },  
    {  
      "self": "example.url...",  
      "value": "C",  
      "id": "example ID"  
    }  
]
```
* instead, you can shorten this to the following and disregard the second part: 



```
"customfield_10047": [      
   {        
      "value": "A"  
   }  
] 
```


### Example Completed Field Reference


Here is a complete JSON Field Reference, with in\-line comments explaining what each custom field pertains to. This is meant as an all\-encompassing example. Your JSON will contain different key values and data points depending on the Custom Values you want to use during issue creation.




```
{  
  "customfield_10050": "https://change-me.com",  
   
  "customfield_10049": "This is a short text custom field",  
   
// two different fields, but both correspond to the same custom date attribute  
  "customfield_10040": "1970-01-01",  
  "customfield_10041": "1970-01-01T03:30:00.000+0200",  
   
// a list of custom labels on a Jira object  
  "customfield_10042": [  
    "custom-label-one",  
    "this-is-default",  
    "change-me-please"  
  ],  
   
// custom number field  
  "customfield_10043": 0,  
   
// custom paragraph field  
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",  
   
// custom radio button field  
  "customfield_10045": {  
    "value": "radio button option"  
  },  
   
// custom multichoice field   
  "customfield_10047": [  
    {  
      "value": "A"  
    }  
  ],  
   
// custom checkbox field  
  "customfield_10039": [  
    {  
      "value": "A"  
    }  
  ],  
   
// custom select list (singlechoice) field  
  "customfield_10048": {  
    "value": "1"  
  }  
}
```


## Step 5 \- Adding the Custom Fields to a DefectDojo Product


You can now add these custom fields to the associated DefectDojo Product, in the Custom Fields section. Once again,


* Navigate to Edit Product \- defectdojo.com/product/ID/edit .
* Navigate to Custom fields and paste the JSON Field Reference as plain text in the Custom Fields box.
* Click ‘Submit’.


## Step 6 \- Testing your Jira Custom Fields from a new Finding:


Now, when you create a new Finding in the Jira\-associated Product, Jira will automatically create all of these Custom Fields in Jira according to the JSON block contained within. These Custom Fields will be created with the default (“change\-me\-please”, etc.) values.



Within the Product on DefectDojo, navigate to the Findings \> Add New Finding page. Make sure the Finding is both Active and Verified to ensure that it pushes to Jira, and then confirm on the Jira side that the Custom Fields are successfully created without any inconsistencies.


