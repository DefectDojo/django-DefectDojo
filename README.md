# DefectDojo

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-orange.svg)](https://www.owasp.org/index.php/OWASP_DefectDojo_Project) [![GitHub release](https://img.shields.io/github/release/DefectDojo/django-DefectDojo.svg)](https://github.com/DefectDojo/django-DefectDojo) [![YouTube Subscribe](https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg)](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) ![Twitter Follow](https://img.shields.io/twitter/follow/defectdojo.svg?style=social&label=Follow)

[![Unit Tests](https://github.com/DefectDojo/django-DefectDojo/actions/workflows/unit-tests.yml/badge.svg?branch=master)](https://github.com/DefectDojo/django-DefectDojo/actions)[![Integration Tests](https://github.com/DefectDojo/django-DefectDojo/actions/workflows/integration-tests.yml/badge.svg?branch=master)](https://github.com/DefectDojo/django-DefectDojo/actions) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2098/badge)](https://bestpractices.coreinfrastructure.org/projects/2098)

![Screenshot of DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/screenshot1.png)

[DefectDojo](https://www.defectdojo.com/) is a security orchestration and
vulnerability management platform.
DefectDojo allows you to manage your application security program, maintain
product and application information, triage vulnerabilities and
push findings to systems like JIRA and Slack. DefectDojo enriches and
refines vulnerability data using a number of heuristic algorithms that
improve with the more you use the platform.

## Demo

Try out the demo server at [demo.defectdojo.org](https://demo.defectdojo.org)

Log in with `admin / 1Defectdojo@demo#appsec`. Please note that the demo is publicly accessible and regularly reset. Do not put sensitive data in the demo.

## Quick Start

```sh
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
# building
./dc-build.sh
# running (for other profiles besides mysql-rabbitmq look at https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md)
./dc-up.sh mysql-rabbitmq
# obtain admin credentials. the initializer can take up to 3 minutes to run
# use docker-compose logs -f initializer to track progress
docker-compose logs initializer | grep "Admin password:"
```

Navigate to <http://localhost:8080>.


## Documentation

- [Official Docs](https://defectdojo.github.io/django-DefectDojo/) ([latest](https://defectdojo.github.io/django-DefectDojo/) | [dev](https://defectdojo.github.io/django-DefectDojo/dev))
- [REST APIs](https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/)
- [Client APIs and Wrappers](https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/#clients--api-wrappers)
- [Authentication Options](readme-docs/AVAILABLE-PLUGINS.md)
- [Parsers](https://defectdojo.github.io/django-DefectDojo/integrations/parsers/)

## Supported Installation Options

* [Docker / Docker Compose](readme-docs/DOCKER.md)
* [SaaS](https://www.defectdojo.com/pricing) - Includes Support & Supports the Project
* [AWS AMI ](https://aws.amazon.com/marketplace/pp/prodview-m2a25gr67xbzk) - Supports the Project
* [godojo](https://github.com/DefectDojo/godojo)


## Community, Getting Involved, and Updates

[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/slack-logo-icon.png" alt="Slack" height="50"/>](https://owasp-slack.herokuapp.com/)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Linkedin-logo-icon-png.png" alt="LinkedIn" height="50"/>](https://www.linkedin.com/company/defectdojo)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Twitter_Logo.png" alt="Twitter" height="50"/>](https://twitter.com/defectdojo)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/YouTube-Emblem.png" alt="Youtube" height="50"/>](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ)

[Join the slack community](https://owasp-slack.herokuapp.com/) and discussion! Realtime discussion is done in the OWASP Slack Channel, #defectdojo.
Follow DefectDojo on [Twitter](https://twitter.com/defectdojo), [Linkedin](https://www.linkedin.com/company/defectdojo), and [YouTube](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) for project updates!

## Contributing
See our [Contributing guidelines](readme-docs/CONTRIBUTING.md)

## Commercial Support and Training
Commercial support and training is availaible through [10Security](https://10security.com).

10Security was founded by the creators of DefectDojo.
For information please email info@10security.com or visit our [site](https://10security.com).

## About Us

DefectDojo is maintained by:
* Greg Anderson ([@devGregA](https://github.com/devgrega) | [linkedin](https://www.linkedin.com/in/g-anderson/))
* Aaron Weaver ([@aaronweaver](https://github.com/aaronweaver)| [linkedin](https://www.linkedin.com/in/aweaver/) | [@weavera](https://twitter.com/weavera))
* Matt Tesauro ([@mtesauro](https://github.com/mtesauro) | [linkedin](https://www.linkedin.com/in/matttesauro/) | [@matt_tesauro](https://twitter.com/matt_tesauro))

Core Moderators can help you with pull requests or feedback on dev ideas:
* Cody Maffucci ([@Maffooch](https://github.com/maffooch) | [linkedin](https://www.linkedin.com/in/cody-maffucci))

Moderators can help you with pull requests or feedback on dev ideas:
* Damien Carol ([@damnielcarol](https://github.com/damiencarol) | [linkedin](https://www.linkedin.com/in/damien-carol/))
* Stefan Fleckenstein ([@StefanFl](https://github.com/stefanfl) | ([linkedin](https://www.linkedin.com/in/stefan-fleckenstein-6a456a30/))
* Jannik Jürgens ([@alles-klar](https://github.com/alles-klar))


## Hall of Fame
* Valentijn Scholten ([@valentijnscholten](https://github.com/valentijnscholten) | [sponsor](https://github.com/sponsors/valentijnscholten) | [linkedin](https://www.linkedin.com/in/valentijn-scholten/)) - Valentijn served as a core moderator for 3 years. Valentijn’s contributions were numerous and extensive. He overhauled, improved, and optimized many parts of the codebase. He consistently fielded questions, provided feedback on pull requests, and provided a helping hand wherever it was needed.
* Fred Blaise ([@madchap](https://github.com/madchap) | [linkedin](https://www.linkedin.com/in/fredblaise/)) - Fred served as a core moderator during a critical time for DefectDojo. He contributed code, helped the team stay organized, and architected important policies and procedures.
* Charles Neill ([@ccneill](https://twitter.com/ccneill)) – Charles served as a
    DefectDojo Maintainer for years and wrote some of Dojo's core functionality.
* Jay Paz ([@jjpaz](https://twitter.com/jjpaz)) – Jay was a DefectDojo
  maintainer for years. He performed Dojo's first UI overhaul, optimized code structure/features, and added numerous enhancements.


## Security

Please report Security issues via our [disclosure policy](readme-docs/SECURITY.md).

## License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
