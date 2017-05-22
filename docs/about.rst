About DefectDojo
================

DefectDojo Basics
~~~~~~~~~~~~~~~~~

Terms
*****
There are several terms that will be helpful to understand as you work with DefectDojo

Products
********
This is the name of any project, program, team, or company that you are currently testing.

*Examples*
	* OpenStack Neutron
	* Internal wiki
	* Hipchat

Product types
*************
These can be business unit divisions, different offices or locations, or any other logical way of distinguishing "types" of products.

*Examples*
	* Internal / 3rd party
	* Main company / Acquisition
	* San Francisco / New York offices

Engagements
***********
Engagements are moments in time when testing is taking place. They are associated with a name for easy reference, a time line, a lead (the user account of the main person conducting the testing), a test strategy, and a status.

*Examples*
	* Beta
	* Quarterly PCI Scan
	* Release Version X

Test Types
**********
These can be any sort of distinguishing characteristic about the type of testing that was done during an Engagement.

*Examples*
	* Functional
	* Security
	* Nessus Scan
	* API test

Development Environments
************************
These describe the environment that was tested during a particular Engagement.

*Examples*
	* Production
	* Staging
	* Stable

Projects that extend DefectDojo
*******************************
In an effort to keep the main Defectdojo functionality as separate from our own needs as possible, the Rackspace Security Engineering team have made it possible to extend DefectDojo without the need to hack it or look under the hood. Some of the projects that extend DefectDojo as Django apps are as follows:

* `DefectDojo Engagement Survey`_.
This project extends django-DefectDojo by incorporating survey(s) associated with each engagement to help develop a test strategy. The questions within these surveys have been created by the Rackspace Security Engineering team to help identify the attack vectors and risks associated with the product being assessed.
.. _DefectDojo Engagement Survey:  https://github.com/grendel513/defectDojo-engagement-survey 





