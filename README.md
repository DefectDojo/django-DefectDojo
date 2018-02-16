# Description

![Screenshot of DefectDojo](./doc/img/screenshot1.png)

DefectDojo is a security program and vulnerability management tool. DefectDojo allows you to manage your application security program, maintain product and application information, schedule scans, triage vulnerabilities and push findings into defect trackers. Consolidate your findings into one source of truth with DefectDojo.

[![Build Status](https://travis-ci.org/DefectDojo/django-DefectDojo.svg?branch=master)](https://travis-ci.org/DefectDojo/django-DefectDojo) [![Documentation Status](https://readthedocs.org/projects/defectdojo/badge/?version=latest)](https://defectdojo.readthedocs.io/en/latest/?badge=latest)


# Quick Start

```bash
$ git clone https://github.com/DefectDojo/django-DefectDojo
$ cd django-DefectDojo
$ ./setup.bash
$ ./run_dojo.bash
```

navigate to `127.0.0.1:8000`

# Demo

If you'd like to check out a demo of DefectDojo before installing it, you can
check out our [PythonAnywhere demo site](https://defectdojo.pythonanywhere.com/).

You can log in as an administrator like so:

![Admin](./doc/img/admin.png)

You can also log in as a product owner / non-staff user:

![Product owner](./doc/img/owner.png)

# Additional Documentation

For additional documentation you can visit our [Read the Docs site](https://defectdojo.readthedocs.io/).

# One-Click Installations

Deploy to Docker Cloud. (__Login first to Docker Cloud before clicking the install button.__)

[![Deploy to Docker Cloud](https://files.cloud.docker.com/images/deploy-to-dockercloud.svg)](https://cloud.docker.com/stack/deploy/?repo=https://github.com/aaronweaver/docker-DefectDojo)

# Installation Options

### [Debian, Ubuntu (16.04.2+) or RHEL-based Install Script](https://defectdojo.readthedocs.io/en/latest/getting-started.html#install-script)

### [Docker](https://defectdojo.readthedocs.io/en/latest/getting-started.html#docker-local-install)

### [Ansible](./ansible/prod-install)

# Getting Started

We recommend checking out the [about](https://defectdojo.readthedocs.io/en/latest/about.html) document to learn the
terminology of DefectDojo, and the
[getting started guide](https://defectdojo.readthedocs.io/en/latest/getting-started.html) for setting up a new
installation. We've also created some example [workflows](https://defectdojo.readthedocs.io/en/latest/workflows.html)
that should give you an idea of how to use DefectDojo for your own team.

# DefectDojo Client API's

- DefectDojo Python API: `pip install defectdojo_api` or clone the [repository](https://github.com/aaronweaver/defectdojo_api).

# Getting Involved

![Slack](./doc/img/slack_rgb.png)

[Get Access.](https://owasp.herokuapp.com/)   Realtime discussion is done in the OWASP Slack Channel, #defectdojo.

![Twitter](./doc/img/Twitter_Logo.png)

[DefectDojo Twitter Account](https://twitter.com/defect_dojo)  tweets project updates and changes.

# Available Plugins

[Engagement Surveys](https://github.com/grendel513/defectDojo-engagement-survey) - A plugin that adds answerable surveys to engagements.

[LDAP Integration](https://django-auth-ldap.readthedocs.io/en/latest/)

[SAML Integration](https://pypi.python.org/pypi/djangosaml2/)

[Multi-Factor Auth](https://django-mfa.readthedocs.io/en/latest/)


# About Us

DefectDojo is maintained by:

- Greg Anderson
- Charles Neill ([@ccneill](https://twitter.com/ccneill))
- Jay Paz ([@jjpaz](https://twitter.com/jjpaz))
- Aaron Weaver ([@weavera](https://twitter.com/weavera))
- Matt Tesauro ([@matt_tesauro](https://twitter.com/matt_tesauro))

# Contributing

We greatly appreciate all of our [contributors](https://github.com/DefectDojo/django-DefectDojo/graphs/contributors).

We would also like to highlight the contributions from Michael Dong and Fatimah Zohra who contributed to DefectDojo before it was open source.

### Swag Rewards
If you fix an issue with the `swag reward` tag,  we'll send you a shirt and some stickers!

![Dojo tshirt front](./doc/img/dojo_tshirt_front.png)
![Dojo tshirt back](./doc/img/dojo_tshirt_back.png)


# Support

Proceeds are used for testing, infrastructure, etc.

[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=paypal%40owasp%2eorg&lc=US&item_name=OWASP%20DefectDojo&no_note=0&currency_code=USD&bn=PP%2dDonationsBF)

# Sponsors

[![Xing](./doc/img/XING_logo.png)](https://corporate.xing.com/en/about-xing/security/)

Interested in becoming a sponsor and having your logo displayed? Please email greg.anderson@owasp.org

# License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
