# DefectDojo

<table>
   <tr styl="margin: 0; position: absolute; top: 50%; -ms-transform: translateY(-50%); transform: translateY(-50%);">
     <th><a href="https://opensourcesecurityindex.io/" target="_blank" rel="noopener">
         <img style="width: 282px; height: 56px" src="https://opensourcesecurityindex.io/badge.svg"
           alt="Open Source Security Index - Fastest Growing Open Source Security Projects" width="282" height="56" />
       </a></th>
     <th>
       <p><a href="https://www.owasp.org/index.php/OWASP_DefectDojo_Project"><img
             src="https://img.shields.io/badge/owasp-flagship%20project-orange.svg" alt="OWASP Flagship"></a> <a
           href="https://github.com/DefectDojo/django-DefectDojo"><img
             src="https://img.shields.io/github/release/DefectDojo/django-DefectDojo.svg" alt="GitHub release"></a> <a
           href="https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ"><img
             src="https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg" alt="YouTube Subscribe"></a> <img
           src="https://img.shields.io/twitter/follow/defectdojo.svg?style=social&amp;label=Follow" alt="Twitter Follow">
       </p>
       <p><a href="https://github.com/DefectDojo/django-DefectDojo/actions"><img
             src="https://github.com/DefectDojo/django-DefectDojo/actions/workflows/unit-tests.yml/badge.svg?branch=master"
             alt="Unit Tests"></a><a href="https://github.com/DefectDojo/django-DefectDojo/actions"><img
             src="https://github.com/DefectDojo/django-DefectDojo/actions/workflows/integration-tests.yml/badge.svg?branch=master"
             alt="Integration Tests"></a> <a href="https://bestpractices.coreinfrastructure.org/projects/2098"><img
             src="https://bestpractices.coreinfrastructure.org/projects/2098/badge" alt="CII Best Practices"></a></p>
     </th>
   </tr>
 </table>

![Screenshot of DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/screenshot1.png)

[DefectDojo](https://www.defectdojo.com/) is a DevSecOps, ASPM (application security posture management), and vulnerability management tool.
DefectDojo ​​orchestrates end-to-end security testing, vulnerability tracking, deduplication, remediation, and reporting.

## Demo

Try out the demo server at [demo.defectdojo.org](https://demo.defectdojo.org)

Log in with `admin / 1Defectdojo@demo#appsec`. Please note that the demo is publicly accessible and regularly reset. Do not put sensitive data in the demo.

## Quick Start for Compose V2
From July 2023 Compose V1 [stopped receiving updates](https://docs.docker.com/compose/reference/).

Compose V2 integrates compose functions into the Docker platform, continuing to support most of the previous docker-compose features and flags. You can run Compose V2 by replacing the hyphen (-) with a space, using `docker compose`, instead of `docker-compose`.

```sh
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
# building
./dc-build.sh
# running (for other profiles besides postgres-redis look at https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md)
./dc-up.sh postgres-redis
# obtain admin credentials. the initializer can take up to 3 minutes to run
# use docker-compose logs -f initializer to track progress
docker compose logs initializer | grep "Admin password:"
```
## For Docker Compose V1
You can run Compose V1 by editing the below files to add the hyphen (-) between `docker compose`. 
```sh
     dc-build.sh
     dc-down.sh
     dc-stop.sh
     dc-unittest.sh
     dc-up-d.sh
     dc-up.sh
     docker/docker-compose-check.sh
     docker/entrypoint-initializer.sh
     docker/setEnv.sh
```


Navigate to <http://localhost:8080>.


## Documentation

- [Official Docs](https://documentation.defectdojo.com/) ([latest](https://documentation.defectdojo.com/) | [dev](https://documentation.defectdojo.com/dev))
- [REST APIs](https://documentation.defectdojo.com/integrations/api-v2-docs/)
- [Client APIs and Wrappers](https://documentation.defectdojo.com/integrations/api-v2-docs/#clients--api-wrappers)
- [Authentication Options](readme-docs/AVAILABLE-PLUGINS.md)
- [Parsers](https://documentation.defectdojo.com/integrations/parsers/)

## Supported Installation Options

* [Docker / Docker Compose](readme-docs/DOCKER.md)
* [SaaS](https://www.defectdojo.com/pricing) - Includes Support & Supports the Project
* [AWS AMI](https://aws.amazon.com/marketplace/pp/prodview-m2a25gr67xbzk) - Supports the Project

## Community, Getting Involved, and Updates

[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/slack-logo-icon.png" alt="Slack" height="50"/>](https://owasp-slack.herokuapp.com/)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Linkedin-logo-icon-png.png" alt="LinkedIn" height="50"/>](https://www.linkedin.com/company/defectdojo)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Twitter_Logo.png" alt="Twitter" height="50"/>](https://twitter.com/defectdojo)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/YouTube-Emblem.png" alt="Youtube" height="50"/>](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ)

[Join the slack community](https://owasp.org/slack/invite) and discussion! Realtime discussion is done in the OWASP Slack Channel, #defectdojo.
Follow DefectDojo on [Twitter](https://twitter.com/defectdojo), [Linkedin](https://www.linkedin.com/company/defectdojo), and [YouTube](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) for project updates!

## Contributing

:warning: Please note that DefectDojo will soon stop accepting new features to stabilize the API and data model for a
forthcoming v3 release. See the contributing guidelines below for more details. :warning:

See our [Contributing guidelines](readme-docs/CONTRIBUTING.md)

## Pro Edition
[Upgrade to DefectDojo Pro](https://www.defectdojo.com/pricing) today to take your DevSecOps to 11. DefectDojo Pro is designed to meet you wherever you are on your security journey and help you scale, with enhanced dashboards, additional smart features, tunable deduplication, and support from DevSecOps experts.

Alternatively, for information please email info@defectdojo.com

## About Us

DefectDojo is maintained by:
* Greg Anderson ([@devGregA](https://github.com/devgrega) | [linkedin](https://www.linkedin.com/in/g-anderson/))
* Matt Tesauro ([@mtesauro](https://github.com/mtesauro) | [linkedin](https://www.linkedin.com/in/matttesauro/) | [@matt_tesauro](https://twitter.com/matt_tesauro))

Core Moderators can help you with pull requests or feedback on dev ideas:
* Cody Maffucci ([@Maffooch](https://github.com/maffooch) | [linkedin](https://www.linkedin.com/in/cody-maffucci))

Moderators can help you with pull requests or feedback on dev ideas:
* Damien Carol ([@damnielcarol](https://github.com/damiencarol) | [linkedin](https://www.linkedin.com/in/damien-carol/))
* Jannik Jürgens ([@alles-klar](https://github.com/alles-klar))
* Dubravko Sever ([@dsever](https://github.com/dsever))


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

DefectDojo is licensed under the [BSD 3-Clause License](LICENSE.md)
