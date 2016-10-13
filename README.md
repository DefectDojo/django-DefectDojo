# Description

![Screenshot of DefectDojo](./doc/img/screenshot1.png)

DefectDojo is a tool created by the Security Engineering team at Rackspace to
track testing efforts. It attempts to streamline the testing process by
offering features such as templating, report generation, metrics, and baseline
self-service tools. Though it was designed with security folks in mind, there
is nothing keeping QA/QE testers, or any other testers for that matter, from
using it productively.

# Demo

If you'd like to check out a demo of DefectDojo before installing it, you can
check out our [PythonAnywhere demo site](http://defectdojo.pythonanywhere.com/).

You can log in as an administrator like so:

![Admin](https://inventropy.us/dd/admin.png)

You can also log in as a product owner / non-staff user:

![Product owner](https://inventropy.us/dd/owner.png)

# Additional Documentation

For additional documentation you can visit our [Read the Docs site](http://defectdojo.readthedocs.io/).

# Installation

[![Build Status](https://travis-ci.org/OWASP/django-DefectDojo.svg?branch=master)](https://travis-ci.org/OWASP/django-DefectDojo)

### [Debian or RHEL-based Install Script](./doc/install_bash.md)
Jay has also created a detailed guide for setting up DefectDojo on 
[Ubuntu 14.04](https://github.com/rackerlabs/django-DefectDojo/wiki/DefectDojo-Installation-Guide---Ubuntu-Desktop-14.04).

### [Docker](http://defectdojo.readthedocs.io/en/latest/getting-started.html#docker-local-install)

### [Vagrant (deprecated)](./doc/install_vagrant.md)

# Getting Started

We recommend checking out the [about](./doc/about.md) document to learn the 
terminology of DefectDojo, and the
[getting started guide](./doc/getting_started.md) for setting up a new
installation. We've also created some example [workflows](./doc/workflows.md)
that should give you an idea of how to use DefectDojo for your own team.

# Getting Involved

Realtime discussion is done in the OWASP Slack Channel, #defectdojo. [Get Access.](https://owasp.herokuapp.com/)

We discuss updates and changes on the [DefectDojo OWASP Mailing List](https://lists.owasp.org/mailman/listinfo/owasp_defectdojo_project).

The [DefectDojo Twitter Account](https://twitter.com/defect_dojo) tweets project updates and changes.

# Available Plugins

[Engagement Surveys](https://github.com/grendel513/defectDojo-engagement-survey) - A plugin that adds answerable surveys to engagements.

[LDAP Integration](https://pythonhosted.org/django-auth-ldap/)

[SAML Integration](https://pypi.python.org/pypi/djangosaml2/)


# About Us

DefectDojo is maintained by:

- Greg Anderson ([@\_GRRegg](https://twitter.com/_GRRegg))
- Charles Neill ([@ccneill](https://twitter.com/ccneill))
- Jay Paz ([@jjpaz](https://twitter.com/jjpaz))
- Aaron Weaver ([@weavera] (https://twitter.com/weavera))

With past contributions from:

- Fatimah Zohra
- Michael Dong

# Support

Proceeds are used for testing infrastrucutre, etc.

[Stickers](https://www.stickermule.com/en/marketplace/tags/defectdojo)

[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=paypal%40owasp%2eorg&lc=US&item_name=OWASP%20DefectDojo&no_note=0&currency_code=USD&bn=PP%2dDonationsBF)

# License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
