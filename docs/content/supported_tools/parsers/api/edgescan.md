---
title: "Edgescan"
toc_hide: true
---
Import Edgescan vulnerabilities by API or [JSON file](../../file/edgescan).

All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

**Step 1: Add tool configuration**

- Select the gear icon from the left hand side of the page.
- Click on the `Tool Configuration` option and then `+ Add Tool Configuration` from the dropdown menu.
- Once presented with a series of fields, set `Tool Type` to "Edgescan" and `Authentication Type` to "API Key".
- Paste your Edgescan API key in the `API Key` field.
- Click on the `Submit` button.

**Step 2: Add and configure a product**

- Select the hamburger menu icon from the left hand side of the page.
- Click on the `All Products` option and then `+ Add Product`.
- Fill in the fields presented.
- Once the product is added, click on the `Settings` option then `Add API Scan Configuration`.
- Select the previously added Edgescan `Tool Configuration`. 
- Provide the edgescan asset ID(s) that you wish to import the findings for in the field `Service key 1`. 
    - Note that multiple asset IDs should be comma separated with no spacing.
    - If you want to import vulnerabilities for all assets, simply leave the Service key 1 field empty.

**Step 3: Importing scan results**

- After the previous steps are complete, you can import the findings by selecting the `Findings` option
on the product's page and then `Import Scan Results`.
- Once you are presented with a series of fields, select `Edgescan Scan` as the scan type. 
    - If you have more than one asset configured, you must also select which Edgescan `API Scan Configuration` to use.
- Click on the `Import` button.

**Important Reminder:**

- To ensure you're not introducing duplicate vulnerabilities, always use the "Re-Upload Scan" option when re-importing findings from Edgescan. This can be found within the engagement's options by clicking on `Engagements` , then the active engagement in question, then `Edgescan Scan` and selecting "Re-Upload Scan" from the dropdown menu located on the right.
