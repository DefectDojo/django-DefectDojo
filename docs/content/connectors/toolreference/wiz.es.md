---
title: "Wiz"
description: "Cómo configurar el Conector Upstream de Wiz para DefectDojo"
weight: 142
audience: pro
---
Para usar el conector de Wiz es necesario crear una cuenta de servicio: consulte la [documentación de Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) para más información. Necesitará una cuenta de Wiz para acceder a la documentación.

La cuenta de servicio debe cumplir todos los siguientes requisitos. Una cuenta de servicio a la que le falte alguno de ellos aún puede autenticarse correctamente, pero no importará nada:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: como mínimo `read:projects`, `read:issues`, y `read:vulnerabilities`.
* **Project visibility**: la cuenta de servicio debe tener alcance sobre cada Wiz Project que desee importar (o sobre todos los Projects). El conector descubre primero sus Wiz Projects y luego obtiene los hallazgos de cada Project — una cuenta que puede leer issues pero no tiene visibilidad de Projects descubre cero Projects, por lo que no hay nada que importar y ninguno de los dos lados reporta un error.

#### **Asignaciones del conector**

1. Introduzca su Wiz Client ID en el campo Client ID.
2. Introduzca el Wiz Client Secret en el campo Secret.
