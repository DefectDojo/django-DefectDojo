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

### [Debian or RHEL-based Install Script](./doc/install_bash.md)
Jay has also created a detailed guide for setting up DefectDojo on 
[Ubuntu 14.04](https://github.com/rackerlabs/django-DefectDojo/wiki/DefectDojo-Installation-Guide---Ubuntu-Desktop-14.04).

### [Vagrant](./doc/install_vagrant.md)

### [Docker](http://defectdojo.readthedocs.io/en/latest/getting-started.html#docker-local-install)

# Getting Started

We recommend checking out the [about](./doc/about.md) document to learn the 
terminology of DefectDojo, and the
[getting started guide](./doc/getting_started.md) for setting up a new
installation. We've also created some example [workflows](./doc/workflows.md)
that should give you an idea of how to use DefectDojo for your own team.

# Getting Involved

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

With past contributions from:

- Fatimah Zohra
- Michael Dong

# License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
