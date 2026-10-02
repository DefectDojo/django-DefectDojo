---
title: "SonarQube"
description: "Cómo configurar el Conector Upstream de SonarQube para DefectDojo"
weight: 127
audience: pro
---
El conector de SonarQube puede obtener datos tanto de una cuenta de SonarCloud como de una instancia local de SonarQube.

**Para usuarios de SonarCloud:**

1. Ingrese https://sonarcloud.io/ en el campo Location.
2. Ingrese una **API key** válida en el campo Secret.

**Para usuarios de SonarQube (on-premise):**

1. Ingrese la URL base de su instancia de SonarQube en el campo Location: por ejemplo, `https://my.sonarqube.com/`
2. Ingrese una **API key** válida en el campo Secret. Deberá ser un **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

El token deberá tener acceso a Projects, Vulnerabilities y Hotspots dentro de Sonar.

Los tokens de API se pueden encontrar y generar a través de **My Account -> Security -> Generate Token** en la aplicación de SonarQube. Para más información, [consulte la documentación de SonarQube](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).
