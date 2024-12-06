---
title: "Add or Edit a Connector"
description: "Connect to a supported security tool"
---

The process for adding and configuring a connector is similar, regardless of the tool you’re trying to connect. However, certain tools may require you to create API keys or complete additional steps.

Before you begin this process, we recommend checking our [tool-specific reference](https://docs.defectdojo.com/en/connecting_your_tools/connectors/connectors_tool_reference/) to find the API resources for the tool you're trying to connect.

1. If you haven't already, start by **switching to the Beta UI** in DefectDojo.
2. From the left\-side menu, click on the **API Connectors** menu item. This is nested under the **Import** header.
​
![image](images/add_edit_connectors.png)
3. Choose a new Connector you want to add to DefectDojo in **Available Connections**, and click the **Add Configuration** underneath the tool.  
​  
You can also edit an existing Connection under the **Configured Connections** header. Click **Manage Configuration \> Edit Configuration** for the Configured Connection you want to Edit.  
​
![image](images/add_edit_connectors_2.png)

4. You will need an accessible URL **Location** for the tool, along with an API **Secret** key. The location of the API key will depend on the tool you are trying to configure. See our [Tool\-Specific Reference](https://docs.defectdojo.com/en/connecting_your_tools/connectors/connectors_tool_reference/) for more details.  
​
5. Set a **Label** for this connection to help you identify it in DefectDojo.  
​
6. Schedule the **Connector’s** automatic Discovery and Synchronization activities. These can be changed later.  
​
7. Select whether you wish to **Enable Auto\-Mapping**. Enable Auto\-Mapping will create a new Product in DefectDojo to store the data from this connector. Auto\-Mapping can be turned on or off at any time.  
​
8. Click **Submit.**

![image](images/add_edit_connectors_3.png)

## Next Steps

* Now that you've added a connector, you can confirm everything is set up correctly by running a [Discover](https://docs.defectdojo.com/en/connecting_your_tools/connectors/operations_discover/) operation.
