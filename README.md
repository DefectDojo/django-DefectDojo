# Running "producion-like docker" instance

Things to know:
* we use the directory you're working in (which should get this one on your machine) to mount and create most of the data we need
* edit .env_dojo and .env_mysql to fit your needs, DONT CHECK THEM IN WITH YOUR EDITS
  * note: yeah I know I should fix this
* most important setting...FLUSHDB in .env_dojo you probably only want this set to y once and on subsequent docker-compose up's, set it to "n"
* lots of clean up work needs to transpire, to get this to 100% awesome I'd need to work with upstream which could take looots of time and arguing
* I used jinja2 instead of sed inasnity to template out settings.py, yes I know django has a template engine, but this was just faster and cleaner



Questions: 
* why did you do this? 
  * needed to make this run in "prod" for someone, the repo makes it kinda hard to do that with docker
* wouldn't you like to be a pepper to? 
  * sometimes
* can/will you make this more better? Depends on if there's a lot of demand for it, the orginal intent here was to get something running 
then revist this once we're confident this thing fits the bill. 
 

# Description

![Screenshot of DefectDojo](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/screenshot1.png)

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

![Admin](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/admin.png)

You can also log in as a product owner / non-staff user:

![Product owner](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/owner.png)

# Additional Documentation

For additional documentation you can visit our [Read the Docs site](https://defectdojo.readthedocs.io/).

# Installation Options

### [Debian, Ubuntu (16.04.2+) or RHEL-based Install Script](https://defectdojo.readthedocs.io/en/latest/getting-started.html#install-script)

### [Docker](https://defectdojo.readthedocs.io/en/latest/getting-started.html#docker-local-install)

### [Ansible](https://raw.githubusercontent.com/DefectDojo/Documentation/master/ansible/prod-install)

# Getting Started

We recommend checking out the [about](https://defectdojo.readthedocs.io/en/latest/about.html) document to learn the
terminology of DefectDojo, and the
[getting started guide](https://defectdojo.readthedocs.io/en/latest/getting-started.html) for setting up a new
installation. We've also created some example [workflows](https://defectdojo.readthedocs.io/en/latest/workflows.html)
that should give you an idea of how to use DefectDojo for your own team.

# DefectDojo Client API's

- DefectDojo Python API: `pip install defectdojo_api` or clone the [repository](https://github.com/aaronweaver/defectdojo_api).

# Getting Involved

![Slack](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/slack_rgb.png)

[Get Access.](https://owasp.herokuapp.com/)   Realtime discussion is done in the OWASP Slack Channel, #defectdojo.

![Twitter](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/Twitter_Logo.png)

[DefectDojo Twitter Account](https://twitter.com/defect_dojo)  tweets project updates and changes.

# Available Plugins

[Engagement Surveys](https://github.com/grendel513/defectDojo-engagement-survey) - A plugin that adds answerable surveys to engagements.

[LDAP Integration](https://django-auth-ldap.readthedocs.io/en/latest/)

[SAML Integration](https://pypi.python.org/pypi/djangosaml2/)

[Multi-Factor Auth](https://django-mfa.readthedocs.io/en/latest/)


# About Us

DefectDojo is maintained by:

- [Greg Anderson](https://www.linkedin.com/in/g-anderson/)
- Charles Neill ([@ccneill](https://twitter.com/ccneill))
- Jay Paz ([@jjpaz](https://twitter.com/jjpaz))
- Aaron Weaver ([@weavera](https://twitter.com/weavera))
- Matt Tesauro ([@matt_tesauro](https://twitter.com/matt_tesauro))

# Contributing

We greatly appreciate all of our [contributors](https://github.com/DefectDojo/django-DefectDojo/graphs/contributors).

We would also like to highlight the contributions from Michael Dong and Fatimah Zohra who contributed to DefectDojo before it was open source.

### Swag Rewards
If you fix an issue with the `swag reward` tag,  we'll send you a shirt and some stickers!

![Dojo tshirt front](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/dojo_tshirt_front.png)
![Dojo tshirt back](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/dojo_tshirt_back.png)


# Support

Proceeds are used for testing, infrastructure, etc.

[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=paypal%40owasp%2eorg&lc=US&item_name=OWASP%20DefectDojo&no_note=0&currency_code=USD&bn=PP%2dDonationsBF)

# Sponsors

[![Xing](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/XING_logo.png)](https://corporate.xing.com/en/about-xing/security/)

Interested in becoming a sponsor and having your logo displayed? Please email greg.anderson@owasp.org

# License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
