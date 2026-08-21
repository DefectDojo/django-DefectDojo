---
title: "SonarQube"
description: "How to set up the SonarQube Upstream Connector for DefectDojo"
weight: 127
audience: pro
---
The SonarQube Connector can fetch data from either a SonarCloud account or from a local SonarQube instance.

**For SonarCloud users:**

1. Enter https://sonarcloud.io/ in the Location field.
2. Enter a valid **API key** in the Secret field.

**For SonarQube (on\-premise) users:**

1. Enter the base url of your SonarQube instance in the Location field: for example `https://my.sonarqube.com/`
2. Enter a valid **API key** in the Secret field. This will need to be a **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

The token will need to have access to Projects, Vulnerabilities and Hotspots within Sonar.

API tokens can be found and generated via **My Account \-\> Security \-\> Generate Token** in the SonarQube app. For more information, [see SonarQube documentation](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).
