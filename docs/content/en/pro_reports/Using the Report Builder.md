---
title: "Using the Report Builder"
description: "Build and publish custom reports for external audiences, or your own records"
---

DefectDojo allows you to create Custom Reports for external audiences, which summarize the Findings or Endpoints that you wish to report on. Custom Reports can include branding and boilerplate text, and can also be used as **[Templates](https://support.defectdojo.com/en/articles/9367528-working-with-generated-reports)** for future reports.



# Opening the Report Builder


The Report Builder can be opened from the **📄Reports** page on the sidebar.



![image](images/Using_the_Report_Builder.png)

The report builder page is organized in two columns. The left **Report Format** column is where you can design your report, using widgets from the right **Available Widgets** column.



![image](images/Using_the_Report_Builder_2.png)

# Step 1: Set Report Options



![image](images/Using_the_Report_Builder_3.png)
From the Report Options section, you can take the following actions:


* Set a **Report Name** for the Report or Template
* Include user\-created **Finding Notes** in the report
* Include **Finding Images** in the report
* Upload a header **Image** to the report


## Select a header image for your report


To add an image to the top of your report, click the **Choose File** button and upload an image to DefectDojo.



The image will automatically resize to fit the document, and will render directly above your **Report Name**.




![image](images/Using_the_Report_Builder_4.png)

# Step 2: Add content to your report with Widgets


Once you have set your Report Options, you can begin to design your report using DefectDojo’s widgets.



Widgets are content elements of a report which can be added by dragging and dropping them into the Report Format column. The final Report will be generated based on the position of each Widget, with the **Report Name** and **Header Image** rendered at the top.


* The elements of your report can be reordered by dragging and dropping your widgets into a new order.
* To remove a widget from a report, click and drag it back to the right column.
* Widgets can also be collapsed by clicking on the grey header, for ease in navigation through a report builder.
* The Findings Widget, WYSIWYG Widget and the Endpoints widget can be used more than once.


## Cover Page Widget


The Cover Page Widget allows you to set a Heading, Sub heading and additional metadata for your report. You can only have a single Cover Page for a given Report.


## 


![image](images/Using_the_Report_Builder_5.png)
## Executive Summary Widget


The Executive Summary widget is intended to summarize your report at a glance. It contains a Heading (defaults to Executive Summary), as well as a text box which can contain whatever information you feel is required to summarize the report.



![image](images/Using_the_Report_Builder_6.png)
You can also **Include SLAs** in your executive summary. To add images, markup formatting or anything beyond pure text, consider adding a **WYSIWYG Content Widget** immediately after the executive summary.


* You can only have a single Executive Summary for a given Report.
* If your Report contains multiple SLA configurations (I.E. you have Findings from separate Products which each have their own standards for SLA) each SLA configuration will be listed on the Executive Summary as a separate row.


## Severities Widget


As each organization will have different definitions for each severity level, the Severities Widget allows you to define the Severity Levels used in your report for ease of understanding.



![image](images/Using_the_Report_Builder_7.png)
## Table Of Contents Widget


The Table Of Contents Widget creates a list of each Finding in your report, for quicker access to specific Findings. The table of contents will create a separate heading for each Severity contained within the report. Each Finding listed in the table of contents will have an anchor link attached to quickly jump to the Finding in the report.



![image](images/Using_the_Report_Builder_8.png)
* You can add a section of **Custom Content**, which will add text underneath the Heading.
* You can upload an image to the Table Of Contents by clicking the **Choose File** button next to the **Image** line. The uploaded image will render directly above the **Heading** selected. Images will be resized to fit the document.


## WYSIWYG Content Widget


The WYSIWYG (What You See Is What You Get) widget can be used to add a section containing text and images in your report. Multiple copies of this Widget can be added to add context to other sections of your report.



![image](images/Using_the_Report_Builder_9.png)
* WYSIWYG Content can include an optional Heading.
* Images can be added to a WYSIWYG widget by dragging and dropping them directly into the **Content** box. Images inserted into the Content box will render at their full resolution.
* You can add multiple WYSIWYG widgets to a report.


## Findings Widget


The Findings Widget provides a list and summary of each Finding you want to include in your report. You can set the scope of the Findings you wish to include with Filters.



The Findings Widget is divided into two sections. The upper section contains a list of filters which can be used to determine which Findings you want to include, and the lower section contains the resulting list of Findings after filters are applied. 



To apply filters to your Findings widget, set the filter parameters and click the **Apply Filter** button at the bottom. You can preview the results of your filter by checking the Findings list located underneath the Filters section.



![image](images/Using_the_Report_Builder_10.png)
* As with Widgets, the Filters section can be expanded and collapsed by clicking the gret Filters header.
* You can add multiple separate Findings Widgets to your report with different filter parameters if you want the report to contain more than one list of Findings.
* Only the Findings you are authorized to view are included in these listings, with respect to Role\-Based Access Control

## 


### Example Rendered Finding List



![image](images/Using_the_Report_Builder_11.png)

## Vulnerable Endpoints Widget


The Vulnerable Endpoints widget is similar to the Findings widget. You can use this widget to list all Findings for specific Endpoints, and sort the Finding list by Endpoint instead of by Severity level.



The **Vulnerable Endpoints** widget will list each active Finding for the Endpoints selected. Rather than creating a single list of unsorted Findings this feature will separate them into their Endpoint context.



As with the Findings Widget, the Vulnerable Endpoints Widget is divided into a Filter section and a list of resulting Endpoints from the filter parameters.



![image](images/Using_the_Report_Builder_12.png)
Select the parameters for the Endpoints you wish to include here and click the **Apply Findings** button at the bottom. You can preview the results of your filter by checking the Endpoints list located underneath the Filters section.


* You can add multiple separate Vulnerable Widgets to your report with different filter parameters if you want the report to contain more than one list.
* Only the Findings you are authorized to view are included in these listings, with respect to Role\-Based Access Control.


## \-\-\-\-\-\-\-\-\-\-\-\-\-\- (separator) Widget



This Widget will render a light grey horizontal line to divide between sections.



![image](images/Using_the_Report_Builder_13.png)

# Step 3: Publishing and viewing your Report


Once you have finished building your report, you can generate it by clicking the green ‘**Run’** button at the bottom of the **Report Format** section.



This will automatically take you to the Generated Reports page, and your report will begin to generate in the background. You can check on the Status of your report by reading the Status column next to it, and refreshing the page periodically.



Once your report has generated, you can view it by either clicking on the **Status** (which will be set to ‘Complete: View Report’), or by opening the **⋮** menu next to your report and selecting **View Report**.



![image](images/Using_the_Report_Builder_14.png)

# Step 4: Exporting a Report


Only DefectDojo users will have access to Reports stored in the software, but Reports are set up in a way where they can be exported or printed easily.



The easiest method to use is to Print To PDF \- with an HTML Report open, open a **Print** dialog in your browser and set **Save To PDF** as the **Print Destination**.



![image](images/Using_the_Report_Builder_15.png)

# Report formatting suggestions


* WYSIWYG sections can be used to contextualize or summarize Finding lists. We recommend using this widget throughout your report in between Findings or Vulnerable Endpoints widgets.

