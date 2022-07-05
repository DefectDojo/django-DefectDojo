---
title: "Example workflows"
description: "Two examples how DefectDojo can be used in day-to-day operations."
draft: false
weight: 4
---


Example 1 - Bill the security engineer
--------------------------------------

Bill wants a place to keep track of what he\'s worked on, so that he can
show his boss exactly what issues he reports, and statistics about how
long it takes to close them.

When he is asked to audit an application, Bill registers a new Product
in DefectDojo, and creates a new Engagement. Here he sets some basic
information, like how long he expects the Engagement will take, who will
be leading the testing (himself), what Product he will be working on,
and what tests he will be doing.

Next, he can add a Test to the Engagement, or upload a Nessus scan and
start picking out the real vulnerabilities from the false positives
(Nessus scan Findings are imported as inactive by default).

Within the Test section, Bill can add Findings for any issues that he
has uncovered during his audit. He can assign a severity to the
Findings, describe replication steps, mitigation strategies, and impact
on the system. This will come in handy when he wants to generate a
report to send to the development team responsible for this Product, or
his manager.

Once Bill has completed his Engagement, he can close the Engagement on
the main Engagement page. He can then view the results of his Tests, and
generate a report to send to the development team.

If Bill hears back from the development team that they won\'t be able to
fix the issue for a while, he can make a note of this on the Engagement
page. Bill will also receive Alerts for any bugs that persist longer
than they are supposed to based on their severity.

Example 2 - John the QE manager
-------------------------------

John wants to keep tabs on what his team members are up to, and find
issues that are taking a long time to get fixed. He creates his own
DefectDojo account with superuser privileges so that he can view other
team members\' metrics.

To get a better idea of what his team members are currently working on,
he can start by checking the Calendar. This will show him any active
Engagements that his team is involved in, based on the dates assigned to
those Engagements.

He can view metrics for a Product Type, such as \"Third Party Apps\" to
track his team\'s activity and follow up with Product teams who have
long-lived bugs. He can also look at all the Findings for which there is
a Risk Acceptance associated, and ensure that the proper documentation
or timeline has been provided for the Findings in question.

If he wants to check on a particular team member\'s progress, he can
look at the Engineer Metrics dashboard under \"Additional Metrics\" for
that user.
