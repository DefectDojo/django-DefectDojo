---
title: "Questionnaires"
description: "Collect test scope and deployment information from outsiders."
weight: 3
draft: false
---

## Questionnaires

Questionnaires provide a means for collecting test scope and deployment information from developers and respective stakeholders. DefectDojo includes functionality to create new questionnaires with custom questions, open questionnaires to receive responses for certain time periods from insiders or outsiders, and connect questionnaires with new or existing engagements.

## Creating a New Questionnaire

To access, create, or modify new/existing questionnaires, navigate to the _All Questionnaires_ dashboard from the sidebar.

![Questionnaires Location](../../images/questionnaires-sidebar.png)

On the questionnaire dashboard, all existing questionnaires are displayed. To quickly find a questionnaire, the filters may be used to search for snippets within the questionnaire name and/or description, as well as by active/inactive status.

When questionnaires are open for responses, they will be displayed in the _General Questionnaires_ block towards the bottom of the page.

To begin the process of creating a new questionnaire, select the _Create Questionnaire_ button located in the top right of the questionnaire dashboard.

![Questionnaires Home View](../../images/questionnaires-main-view.png)

Questionnaires have a name and description, as well as an activity status, which are initially set on questionnaire creation, but can be modified in the future if necessary. Once these fields are filled in appropriately, the user can create the questionnaire without any questions (by selecting _Create Questionnaire_), or with questions (by selecting _Create Questionnaire and Add Questions_).

![Create New Questionnaire](../../images/questionnaires-create-new.png)

To add questions to a questionnaire, select the dropdown titled _Select as many Questions as applicable_, which will open all of the existing questions within DefectDojo. Once the desired questions are selected from the list, the dropdown can be closed, and the _Update Questionnaire Questions_ can be selected to save the newly created questionnaire.

_Note_: New questions may also be added at the time of questionnaire creation by selecting the plus located next to the questions dropdown.

![Select Questions](../../images/questionnaires-select-questions.png)

## Creating New Questions

The questions dashboard displays all of the questions that may exist as part of questionnaires within DefectDojo. Similar to questionnaires, to quickly find a question, the filters may be used to search for optional status, or snippets within the question name and/or description. Two types of questions exist within DefectDojo questionnaires: _Text Questions_ and _Multiple Choice Questions_. To add a new question, select the _Create Question_ button located in the top right of the questions dashboard.

![Questionnaire Questions](../../images/questionnaires-questions.png)

#### Adding Text Questions

To add a text question (open-ended), fill out the add question form, where:
 - **Type** - The type of question being created, in this case _Text_.
 - **Order** - The order of a question describes its position in a questionnaire relative to other questions (e.g., an order of _1_ will put the question higher than a question with order _4_).
 - **Optional** - When the optional box is checked, a question will not be required in a questionnaire.
 - **Question Text** - The text that is displayed to prompt a user for their answer (e.g. What is your favorite color?).

![Add Text Answer Question](../../images/questionnaires-open-ended.png)

#### Adding Multiple Choice Questions

Similar to the process of adding a text question, choice questions (non-open-ended) allow the user to pick from a given list of choices. To add a choice question, fill out the add question form, where:
 - **Type** - The type of question being created, in this case _Choice_.
 - **Order** - The order of a question describes its position in a questionnaire relative to other questions (e.g., an order of _1_ will put the question higher than a question with order _4_).
 - **Optional** - When the optional box is checked, a question will not be required in a questionnaire.
 - **Multichoice** - When the multichoice box is checked, multiple choices from the list of choices may be selected by the user.
 - **Answer Choices** - The possible answer choices that may be selected by a user.

![Add Multiple Choice Question](../../images/questionnaires-multiple-choice.png)

## Publishing a Questionnaire

Once a questionnaire has been successfully created, it can be published to accept responses. To publish a questionnaire, select the plus located to the right of _General Questionnaires_.

![Add General Questionnaire](../../images/questionnaires-main-view.png)

This will prompt for a specific questionnaire to be selected, as well as a date the questionnaire response window should close. The response window sets a due date for recipients. Once these two options have been selected, publish the questionnaire by selecting _Add Questionnaire_.

![Publicize Questionnaire](../../images/questionnaires-publicize.png)

Once a questionnaire is published, a link to share it can be retrieved by selecting the _Share Questionnaire_ action. To ensure the newly created questionnaire has been constructed as expected, open the share link and view the newly created questionnaire.

![Share Questionnaire Link](../../images/questionnaires-share.png)

![Responding to Questionnaires](../../images/questionnaires-respond.png)

## Unassigned Questionnaires

When a questionnaire's response window has closed, all of the responses will be saved, and the questionnaire will be listed as an _Unassigned Answered Engagement Questionnaire_ on the DefectDojo dashboard.

There are three actions that may be taken when a questionnaire's response window has closed: _View Responses_, _Create Engagement_, and _Assign User_.

![Unnasigned Questionnaires](../../images/questionnaires-unassigned.png)

#### View Questionnaire Responses

To view the questionnaire responses, select the _View Responses_ action. All of the responses from the questionnaire will be displayed.

![View Questionnaire Responses](../../images/questionnaires-view-responses.png)

#### Create an Engagement From a Questionnaire

To link the questionnaire to a product via an engagement, select the _Create Engagement_ action. Once a product is selected from the dropdown, select _Create Engagement_. This will link the questionnaire results with a new engagement under the selected product, which can then be given specific details similar to other engagements in DefectDojo, such as _Description_, _Version_, _Status_, _Tags_, etc.

![Link Questionnaire to Engagement](../../images/questionnaires-new-engagement.png)

![New Engagement for Questionnaire](../../images/questionnaires-create-engagement.png)

To view a questionnaire at the engagement level, navigate to the engagement linked with the desired questionnaire. Expand the _Additional Features_ menu to reveal a _Questionnaires_ dropdown, which will contain all of the linked questionnaires.

![View Questionnaire from Engagement](../../images/questionnaires-view-questionnaire.png)

#### Assign a Questionnaire to a User

To assign a questionnaire to a user, select the _Assign User_ action. This will prompt for a user to be selected from the dropdown of available users. Once a user is selected, assign the questionnaire to the specified user by selecting _Assign Questionnaire_.

![Assign Questionnaire to User](../../images/questionnaires-assign-user.png)

## Creating Questionnaires From Engagements

While questionnaires are commonly created from the questionnaire dashboard, they can also be created at the engagement level. To create a new questionnaire from within an engagement, expand the _Additional Features_ dropdown to reveal the _Questionnaires_ dropdown. In the right side header of the _Questionnaires_ dropdown, select the plus to link a new questionnaire. 

![New Questionnaire from Engagement](../../images/questionnaires-add-from-engagement.png)

Once prompted, select a questionnaire from the available surveys list to link it with the engagement. If the user wishes to leave a response at the time of linking the questionnaire with the engagement, the _Add Questionnaire and Repond_ option may be selected. To simply link the questionnaire with the engagement, select _Add Questionnaire_.

![Select Questionnaire from Engagement](../../images/questionnaires-select-survey.png)

## Anonymous Questionnaires

Questionnaires, by default, are only accessible by DefectDojo users. To allow outside responses to DefectDojo questionnaires, ensure the _Allow Anonymous Survey Reponses_ option within the _System Settings_ is selected. To share a questionnaire with anonymous users, use the questionnaire's _Share Link_.

![Anonymous Survey Reponses](../../images/questionnaires-system-settings.png)