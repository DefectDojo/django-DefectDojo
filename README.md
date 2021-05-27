# DefectDojo

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-orange.svg)](https://www.owasp.org/index.php/OWASP_DefectDojo_Project) [![GitHub release](https://img.shields.io/github/release/DefectDojo/django-DefectDojo.svg)](https://github.com/DefectDojo/django-DefectDojo) [![YouTube Subscribe](https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg)](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) ![Twitter Follow](https://img.shields.io/twitter/follow/defectdojo.svg?style=social&label=Follow)

[![Build Status](https://github.com/DefectDojo/django-DefectDojo/actions)](https://github.com/DefectDojo/django-DefectDojo/actions) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2098/badge)](https://bestpractices.coreinfrastructure.org/projects/2098)

![Screenshot of DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/screenshot1.png)

[DefectDojo](https://www.defectdojo.org/) is a security program and
vulnerability management tool.
DefectDojo allows you to manage your application security program, maintain
product and application information, triage vulnerabilities and
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

Alternatively, try out the demo sever at [demo.defectdojo.org](https://demo.defectdojo.org)

Log in with `admin / defectdojo@demo#appsec` and please note that the demo server is refreshed regularly.

## Documentation

For detailed documentation you can visit
[Github Pages](https://defectdojo.github.io/django-DefectDojo/).

## Supported Installation Options

* [Docker / Docker Compose](DOCKER.md)
* [godojo](https://github.com/DefectDojo/godojo)

** Now EOL'ed **
* [Setup.bash](https://github.com/DefectDojo/django-DefectDojo/blob/master/setup/README.md)

## Getting Started

We recommend checking out the
[Core Data Classes](https://defectdojo.github.io/usage/models/) document to
learn the terminology of DefectDojo and the
[getting started guide](https://defectdojo.github.io/django-DefectDojo/getting_started/)
for setting up a new installation.
We've also created some example
[workflows](https://defectdojo.github.io/django-DefectDojo/usage/workflows/) that
should give you an idea of how to use DefectDojo for your own team.

## REST APIs

Defectdojo can be accessed through a Swagger REST API. Please see [the API documentation](https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/) or the in-app Swagger documentation.

## Client APIs and wrappers
This section presents different ways to programmatically interact with DefectDojo APIs.

See [Wrappers](WRAPPERS.md)


## Release and branch model
See [Release and branch model](BRANCHING-MODEL.md)


## Roadmap
A magical, illusionary, non-existent, YMMV, wannabe, no guarantees list of thing we may or may not be working on:
- New permission model (underway)
- Push groups of findings to a single JIRA ticket (experimental now in!)
- Reimport matching improvements


## Wishlist
To manage expectations, we call this the wishlist. These are items we want to do, are discussing or pondering our minds:
- New modern UI / SPA
- New dashboarding / statistics
- New search engine
- Adopt a plugin framework to allow plugins for issue trackers, parsers, reports, etc
- More flexible model


## Support, Bug Reports and Getting Involved
Please come to our Slack channel first, where we can try to help you or point you in the right direction:

![Slack](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/slack_rgb.png)

Realtime discussion is done in the OWASP Slack Channel, #defectdojo.
[Get Access.](https://owasp-slack.herokuapp.com/)

## Social Media

![Twitter](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Twitter_Logo.png)

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
* [Cody Maffucci](https://www.linkedin.com/in/cody-maffucci)
* Pascal Trovatelli / [Sopra Steria](https://www.soprasteria.com/)
* [Damien Carol](https://www.linkedin.com/in/damien-carol/)

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

## Sponsors

[![Xing](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/XING_logo.png)](https://corporate.xing.com/en/about-xing/security/)
[![10Security](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/10Security-logo.png)](https://10security.com/services-by-technology/defectdojo-commercial-support/)
[![GCSecurity](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/gc_logo_2018.png)](https://gcsec.com.br/)
[![ISAAC](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/isaac.png)](https://isaac.nl "ISAAC")
[![Timo-Pagel](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/timo-pagel-logo.png )](https://pagel.pro/)
[![SDA-SE](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/sda-se-logo.png)](https://sda-se.com/)
[![Signal-Iduna](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/signal-iduna.png)](https://signal-iduna.de/)
[![WSO2](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/wso2-logo-for-screen.png)](https://wso2.com/)
[![CloudBees](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/cloudbees-logo.png)](https://cloudbees.com/)
[![WeHackPurple](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/WHP.png)](https://wehackpurple.com/)
[![MaibornWolff](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/maibornwolff-logo.png)](https://www.maibornwolff.de/en)


Interested in becoming a sponsor and having your logo displayed? Please review
our [sponsorship information](SPONSORING.md) or email greg.anderson@owasp.org

## License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/DD-Hierarchy.png
