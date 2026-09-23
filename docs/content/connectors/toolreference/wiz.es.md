---
title: "Wiz"
description: "Cómo configurar el Conector Upstream de Wiz para DefectDojo"
weight: 142
audience: pro
---
El conector de Wiz importa **issues y hallazgos de vulnerabilidades**. DefectDojo crea un Record por cada **Wiz Project**, más un Record a nivel de tenant con el nombre del propio tenant, por ejemplo **Wiz Tenant abc12**, que cubre todo el tenant de Wiz.

**No necesita Wiz Projects para usar este conector.** Si su tenant no tiene Projects, asigne el Record ese Record de tenant y DefectDojo importará todos los issues y hallazgos de vulnerabilidades que su cuenta de servicio pueda ver. Ese Record también recoge hallazgos de recursos que ningún Project cubre, así que asígnelo junto a sus Records de Project si sus Projects no lo cubren todo. Si asigna a la vez un Record de Project y el Record ese Record de tenant, los hallazgos de ese Project se importan en dos Assets. Hágalo solo si desea ambas vistas.

Para usar el conector de Wiz es necesario crear una cuenta de servicio: consulte la [documentación de Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) para más información. Necesitará una cuenta de Wiz para acceder a la documentación.

La cuenta de servicio debe cumplir todos los siguientes requisitos. Una cuenta de servicio a la que le falte alguno de ellos aún puede autenticarse correctamente, pero no importará nada:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: como mínimo `read:projects`, `read:issues`, y `read:vulnerabilities`. `read:projects` es necesario incluso en un tenant sin Projects, porque Discover sigue pidiendo la lista de Projects a Wiz.
* **Project visibility**: la cuenta de servicio debe tener alcance sobre cada Wiz Project que desee importar (o sobre todos los Projects). Una cuenta que puede leer issues pero no tiene visibilidad de Projects no descubre ningún Record de Project, y solo queda disponible el Record ese Record de tenant.

#### **Asignaciones del conector**

1. Introduzca su Wiz Client ID en el campo Client ID.
2. Introduzca el Wiz Client Secret en el campo Secret.
