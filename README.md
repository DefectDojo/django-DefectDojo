# DefectDojo

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-orange.svg)](https://www.owasp.org/index.php/OWASP_DefectDojo_Project) [![GitHub release](https://img.shields.io/github/release/DefectDojo/django-DefectDojo.svg)](https://github.com/DefectDojo/django-DefectDojo) [![YouTube Subscribe](https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg)](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) ![Twitter Follow](https://img.shields.io/twitter/follow/defectdojo.svg?style=social&label=Follow)

[![Build Status](https://github.com/DefectDojo/django-DefectDojo/actions)](https://github.com/DefectDojo/django-DefectDojo/actions) [![Documentation Status](https://readthedocs.org/projects/defectdojo/badge/?version=latest)](https://defectdojo.readthedocs.io/en/latest/?badge=latest) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2098/badge)](https://bestpractices.coreinfrastructure.org/projects/2098)

![Screenshot of DefectDojo](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/screenshot1.png)

[DefectDojo](https://www.defectdojo.org/) is a security program and
vulnerability management tool.
DefectDojo allows you to manage your application security program, maintain
product and application information, schedule scans, triage vulnerabilities and
push findings into defect trackers.
Consolidate your findings into one source of truth with DefectDojo.

## Quick Start

```sh
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
# building
docker-compose build
# running
docker-compose up
# obtain admin credentials. the initializer can take up to 3 minutes to run
# use docker-compose logs -f initializer to track progress
docker-compose logs initializer | grep "Admin password:"
```

Navigate to <http://localhost:8080>.

## Documentation

For detailed documentation you can visit
[Read the Docs](https://defectdojo.readthedocs.io/).

## Supported Installation Options

* [Docker / Docker Compose](DOCKER.md)
* [Setup.bash](https://github.com/DefectDojo/django-DefectDojo/blob/master/setup/README.md)(End of Life 31/12/2020)

## Getting Started

We recommend checking out the
[about](https://defectdojo.readthedocs.io/en/latest/about.html) document to
learn the terminology of DefectDojo and the
[getting started guide](https://defectdojo.readthedocs.io/en/latest/getting-started.html)
for setting up a new installation.
We've also created some example
[workflows](https://defectdojo.readthedocs.io/en/latest/workflows.html) that
should give you an idea of how to use DefectDojo for your own team.

## REST APIs

> ** Deprecation notice ** apiv1 is deprecated and EOS is on 12-31-2020. EOL is planned for 06-30-2021.
> Please move on to apiv2 and raise issues for any unsupported operations.

Defectdojo can be accessed through a Swagger REST API. Please see [the API documentation](https://defectdojo.readthedocs.io/en/latest/api-v2-docs.html) or the in-app Swagger documentation.

## Client APIs and wrappers
This section presents different ways to programmatically interact with DefectDojo APIs.

See [Wrappers](WRAPPERS.md)


## Release and branch model
See [Release and branch model](BRANCHING-MODEL.md)


## Support, Bug Reports and Getting Involved
Please come to our Slack channel first, where we can try to help you or point you in the right direction:

![Slack](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/slack_rgb.png)

Realtime discussion is done in the OWASP Slack Channel, #defectdojo.
[Get Access.](https://owasp-slack.herokuapp.com/)

## Social Media

![Twitter](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/Twitter_Logo.png)

[DefectDojo Twitter Account](https://twitter.com/defectdojo) tweets project
updates and changes.

## Available Plugins

[Engagement Surveys](https://github.com/grendel513/defectDojo-engagement-survey)
– A plugin that adds answerable surveys to engagements.

[LDAP Integration](https://django-auth-ldap.readthedocs.io/en/latest/)

[SAML Integration](https://pypi.python.org/pypi/djangosaml2/)

[Multi-Factor Auth](https://django-mfa.readthedocs.io/en/latest/)

## About Us

DefectDojo is maintained by:

* [Greg Anderson](https://www.linkedin.com/in/g-anderson/)
* [Aaron Weaver](https://www.linkedin.com/in/aweaver/) ([@weavera](https://twitter.com/weavera))
* [Matt Tesauro](https://www.linkedin.com/in/matttesauro/) ([@matt_tesauro](https://twitter.com/matt_tesauro))


## Project Moderators

Project Moderators can help you with pull requests or feedback on dev ideas.

* [Alex Dracea](https://www.linkedin.com/in/alexandru-marin-dracea-910b51122/)
* Valentijn Scholten (@valentijnscholten) ([github](https://github.com/valentijnscholten) | [sponsor](https://github.com/sponsors/valentijnscholten) | [linkedin](https://www.linkedin.com/in/valentijn-scholten/))
* Jannik Jürgens
* [Fred Blaise](https://www.linkedin.com/in/fredblaise/)
* Saurabh kumar
* Cody Maffucci
* Pascal Trovatelli / [Sopra Steria](https://www.soprasteria.com/)

## Hall of Fame

* Charles Neill ([@ccneill](https://twitter.com/ccneill)) – Charles served as a
    DefectDojo Maintainer for years and wrote some of Dojo's core functionality.
* Jay Paz ([@jjpaz](https://twitter.com/jjpaz)) – Jay was a DefectDojo
  maintainer for years. He performed Dojo's first UI overhaul, optimized code structure/features, and added numerous enhancements.


## Contributing

We greatly appreciate all of our
[contributors](https://github.com/DefectDojo/django-DefectDojo/graphs/contributors).

More info: [Contributing guideline](CONTRIBUTING.md)

We would also like to highlight the contributions from Michael Dong and Fatimah
Zohra who contributed to DefectDojo before it was open source.

### Swag Rewards

If you fix an issue with the `swag reward` tag,  we'll send you a shirt and some
stickers!

![Dojo tshirt front](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/dojo_tshirt_front.png)

## Support

Proceeds are used for testing, infrastructure, etc.

[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=paypal%40owasp%2eorg&lc=US&item_name=OWASP%20DefectDojo&no_note=0&currency_code=USD&bn=PP%2dDonationsBF)

## Sponsors

[![Xing](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/XING_logo.png)](https://corporate.xing.com/en/about-xing/security/)
[![10Security](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/10Security-logo.png)](https://10security.com/services-by-technology/defectdojo-commercial-support/)
[![GCSecurity](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/gc_logo_2018.png)](https://gcsec.com.br/)
[![ISAAC](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/isaac.png)](https://isaac.nl "ISAAC")
[![Timo-Pagel](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/timo-pagel-logo.png )](https://pagel.pro/)
[![SDA-SE](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/sda-se-logo.png)](https://sda-se.com/)
[![Signal-Iduna](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/signal-iduna.png)](https://signal-iduna.de/)
[![WSO2](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/wso2-logo-for-screen.png)](https://wso2.com/)
[![CloudBees](https://raw.githubusercontent.com/DefectDojo/Documentation/master/doc/img/cloudbees-logo.png)](https://cloudbees.com/)

Interested in becoming a sponsor and having your logo displayed? Please review
our [sponsorship information](SPONSORING.md) or email greg.anderson@owasp.org

## License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
