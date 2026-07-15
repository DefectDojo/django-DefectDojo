---
title: "Add or Edit Upstream Connections"
description: "Connect to a supported security tool"
aliases:
  - /import_data/pro/connectors/add_edit_connectors/
  - /en/connecting_your_tools/connectors/add_edit_connectors
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connections are a DefectDojo Pro-only feature.</span>

The process for adding and configuring an Upstream Connection is similar, regardless of the tool you’re trying to connect. However, certain tools may require you to create API keys or complete additional steps.

Before you begin this process, we recommend checking our [Tool-Specific Reference](../toolreference/) to find the API resources for the tool you're trying to connect.

1. If you haven't already, start by **switching to the Pro UI** in DefectDojo.
2. From the left\-side menu, open the **Connections** group nested under the **Import** header, and click **Upstream Connections**.
​
![image](images/add_edit_connectors.png)

3. Choose a new Connector you want to add to DefectDojo in **Available Connections**, and click the **Add Configuration** button on the tool's tile. You can use the **Search Connections** box to filter each section by tool name, or the **All / Asset / Finding** toggle in the page header to filter by connector type.  
​  
You can also edit an existing Connection under the **Configured Connections** header. Click **Manage Configuration \> Edit Configuration** for the Configured Connection you want to Edit.  
​
![image](images/add_edit_connectors_2.png)

4. You will need an accessible **Location URL** for the tool, along with an API **Secret** key. The location of the API key will depend on the tool you are trying to configure. See our [Tool\-Specific Reference](../toolreference/) for more details.  
​
5. Set a **Label** for this connection to help you identify it in DefectDojo.  
​
6. Schedule the Connector's automatic discovery and sync using the **Discovery Configuration** and **Synchronization Configuration** schedules. These can be changed later.  
​
7. Select whether you wish to **Enable Auto\-Mapping**. Enable Auto\-Mapping will create a new Product in DefectDojo to store the data from this connector. Auto\-Mapping can be turned on or off at any time.  
​
8. Click **Submit.**

![image](images/add_edit_connectors_3.png)

## Next Steps

* Now that you've added a connector, you can confirm everything is set up correctly by running a [Discover](../manage_operations/#discover-operations) operation.
