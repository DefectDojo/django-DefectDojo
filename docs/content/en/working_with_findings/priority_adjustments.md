---
title: "Adjusting Priority and Risk (Pro)"
description: "Change weighting of Priority and Risk calculations"
weight: 2
---

DefectDojo Pro's Priority and Risk calculations can be adjusted, allowing you to tailor DefectDojo Pro to match your internal standards for Finding Priority and Risk.

## Prioritization Engines

Similar to SLA configurations, Prioritization Engines allow you to set the rules governing how Priority and Risk are calculated.

![image](images/priority_default.png)

DefectDojo comes with a built-in Prioritization Engine, which is applied to all Products.  However, you can edit this Prioritization Engine to change the weighting of **Finding** and **Product** multipliers, which will adjust how Finding Priority and Risk are assigned.

### Finding Multipliers

Eight contextual factors impact the Priority score of a Finding.  Three of these are Finding-specific, and the other five are assigned based on the Product that holds the Finding.

You can tune your Prioritization Engine by adjusting how these factors are applied to the final calculation.

![image](images/priority_sliders.png)

Select a factor by clicking the button, and adjust this slider allows you to control the percentage a particular factor is applied.  As you adjust the slider, you'll see the Risk thresholds change as a result.

#### Finding-Level Multipliers

* **Severity** - a Finding's Severity level (Info or Low-Critical)
* **Exploitability** - a Finding's KEV and/or EPSS score
* **Endpoints** - the amount of Endpoints associated with a Finding

#### Product-Level Multipliers

* **Business Criticality** - the related Product's Business Criticality (None, Very Low, Low, Medium, High, or Very
High)
* **User Records** - the related Product's User Records count
* **Revenue** - the related Product's revenue, relative to the total revenue of the Product Type
* **External Audience** - whether or not the related Product has an external audience
* **Internet Accessible** - whether or not the related Product is internet accessible

### Risk Thresholds

Based on the tuning of the Priority Engine, DefectDojo will automatically recommend Risk Thresholds.  However, these thresholds can be adjusted as well and set to whatever values you deem appropriate.

![image](images/risk_threshold.png)

## Creating New Prioritization Engines

You can use multiple Prioritization Engines, which can each be assigned to different Products.

![image](images/priority_engine_new.png)

Creating a new Prioritization Engine will open the Prioritization Engine form.  Once this form is submitted, a new Prioritization Engine will be added to the table.

## Assigning Prioritization Engines to Products

Each Product can have a Prioritization Engine currently in use via the **Edit Product** form for a given Product.

![image](images/priority_chooseengine.png)

Note that when a Product's Prioritization Engine is changed, or a Prioritization Engine is updated, any Findings governed by that Finding will be "Locked"