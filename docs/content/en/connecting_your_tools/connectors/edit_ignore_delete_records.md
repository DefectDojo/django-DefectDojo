---
title: "Edit, Ignore or Delete Records"
description: ""
---

Records can be Edited, Ignored or Deleted from the **Manage Records \& Operations Page.**



Although Mapped and Unmapped records are located in separate tables, they can both be edited in the same way.



From the Records table, click the blue ▼ Arrow next to the State column on a given Record. From there, you can select **Edit Record,** or **Delete Record.**




![](https://defectdojo-inc.intercom-attachments-7.com/i/o/991861519/038163776895e87723a52384/T6IvYbAUMdmrbVWj8fe_rYCn_MzgFXI9aEOu-PvVERtgZ7FjdurerkkobRY3R9uZfBuOO-7okvDSdEdjZLKpvEwbXAKlSHbiTEYOCfmfKXC-_eHsPXdX8sfMlQPL-A-NU9IiVJ5esQtdwcNSlsuD_u0?expires=1729720800&signature=f36d18c3de5b05361f4af20d4e7d3374f1d25358dfeffbf439f3462377d87054&req=fSkmHs9%2FmIBWFb4f3HP0gEja47GdQdb%2B%2BLFrIsBuvBMOnN0G6SdozTFKik%2BB%0AVx0%3D%0A)

# Edit a Record


Clicking **Edit Record** will open a window which allows you to change the destination product in DefectDojo. You can either select an existing Product from the drop\-down menu, or you can type in the name of a new Product you wish to create.




![](https://defectdojo-inc.intercom-attachments-7.com/i/o/991861534/aaf6ffb16062460fa2876879/TRC8bfnFqHV6U3TZgqM92vSVg81pP_WgV1PJ8V4DnZ3dAdHlNTr0jTJdz6ojNOjCI9YQtmpczZQu2nSKMeReW-PLn7fx_kXYdryw2JCpmmlLkzqCHTW-cKnkZmTosww7Yjgm50IIedC-cTD4okrMj28?expires=1729720800&signature=5e419291cf110bce4ca16eb2b22faffc9fedd19e3125b2a994a333d342048612&req=fSkmHs9%2FmIJbFb4f3HP0gIkWHYe6PkjxMsN25eARnSCqNIbbjH8DQpCnmqYa%0AYZQ%3D%0A)

## **Change the Mapping of a Record**


The scan data associated with a Record can be directed to flow into a different Product by changing the mapping. 



Select, or type in the name of a new Product from the drop\-down menu to the right.



## **Edit the State of a Record**


The State of a Record can be changed from this menu as well. Records can be switched from Good to Ignored (or vice versa) by choosing an option from the **State** dropdown list.



### Ignoring a Record


If you wish to ‘switch off’ one of the records or disregard the data it’s sending to DefectDojo, you can choose to ‘Ignore’ the record. An ‘Ignored’ record will move to the Unmapped Records list and will not push any new data to DefectDojo. 


You can Ignore a Mapped Record (which will remove the mapping), or a New Record (from the unmapped Records list).



### Restoring an Ignored Record


If you would like to remove the Ignored status from a record, you can change it back to New with the same State dropdown menu. 


* If Auto\-Map Records is enabled, the Record will return to its original mapping once the Discover operation runs again.  
​
* If Auto\-Map Records is not enabled, DefectDojo will not automatically restore a previous mapping, so you’ll need to set up the mapping for this Record again.



# **Delete a Record**


You can also Delete Records, which will remove them from the Unmapped or Mapped Records table. 



Keep in mind that the Discover function will always import all records from a tool \- meaning that even if a Record is deleted from DefectDojo, it will become re\-discovered later (and will return to the list of Records to be mapped again).



* If you plan on removing the underlying Vendor\-Equivalent Product from your scan tool, then Deleting the Record is a good option. Otherwise, the next Discover operation will see that the associated data is missing, and this Record will change state to 'Missing'.  
​
* However, if the underlying Vendor\-Equivalent Product still exists, it will be Discovered again on a future Discover operation. To prevent this behaviour, you can instead Ignore the Record.

## Does this affect any imported data?


No. All Findings, Tests and Engagements created by a sync record will remain in DefectDojo even after a Record is deleted. Deleting a record or a configuration will only remove the data\-flow process, and won’t delete any vulnerability data from DefectDojo or your tool.




# Next Steps


* If your Records have been mapped, learn how to import data via [Sync operations](https://support.defectdojo.com/en/articles/9124820-sync-operations).
