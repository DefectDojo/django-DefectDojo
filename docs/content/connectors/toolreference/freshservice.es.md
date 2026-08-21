---
title: "Freshservice"
description: "Cómo configurar el Conector Downstream de Freshservice para DefectDojo"
weight: 61
audience: pro
---
La integración con Freshservice le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como tickets de Freshservice, asignados a un Group de agentes de su elección.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con su URL de Freshservice: `https://yourcompany.freshservice.com`.
- **API Key** debe ser una clave de API de Freshservice. Encuéntrela haciendo clic en su foto de perfil (arriba a la derecha) > **Profile settings**: la clave aparece a la derecha, debajo de la sección **Delegate Approvals**, después de completar el captcha. Si no aparece ninguna clave ahí, es posible que el acceso a la API esté deshabilitado a nivel de cuenta y un administrador deba habilitarlo primero.
- **Requester Email** debe ser la dirección de correo en cuyo nombre se solicitan los tickets. Freshservice exige un solicitante en cada ticket, por lo que DefectDojo crea los tickets con esta dirección como solicitante.

### Mapeo del sistema de tickets

- **Group ID** debe ser el ID numérico del Group de agentes de Freshservice al que se asignarán los tickets. Encuéntrelo en la URL al ver el grupo en **Admin > Agent Groups**.
- **Workspace ID** (opcional) enruta los tickets a un espacio de trabajo específico en cuentas con varios espacios de trabajo. Déjelo vacío para usar el espacio de trabajo principal.

### Detalles del mapeo de severidad

Esto se corresponde con el campo **Priority** del ticket de Freshservice, que usa códigos numéricos (`1` Low, `2` Medium, `3` High, `4` Urgent). También se aceptan los nombres de prioridad:

- **Nombre del campo de severidad**: `Priority`
- **Mapeo de Informativa**: `1`
- **Mapeo de Baja**: `1`
- **Mapeo de Media**: `2`
- **Mapeo de Alta**: `3`
- **Mapeo de Crítica**: `4`

### Detalles del mapeo de estado

Esto se corresponde con el campo **Status** del ticket, que usa códigos numéricos (`2` Open, `3` Pending, `4` Resolved, `5` Closed). También se aceptan los nombres de estado:

- **Nombre del campo de estado**: `Status`
- **Mapeo de Activo**: `2`
- **Mapeo de Cerrado**: `5`
- **Mapeo de Falso positivo**: `5`
- **Mapeo de Riesgo aceptado**: `3`

Algunos comportamientos específicos de Freshservice que debe tener en cuenta:

- Las actualizaciones sincronizan el contenido completo del ticket: Freshservice permite editar el asunto y la descripción después de la creación.
- Los tickets se cierran en lugar de eliminarse cuando se elimina un Hallazgo; los tickets ya Resolved o Closed se dejan sin modificar. Se adjunta automáticamente una nota de resolución al cerrar, por lo que las cuentas que exigen una (una regla de negocio habitual) aceptan el cierre.
- Algunas cuentas calculan la prioridad de un ticket a partir de una matriz de Impact/Urgency o de una regla de negocio, e ignoran la prioridad enviada en la creación. DefectDojo detecta esto y vuelve a aplicar la prioridad mapeada con una actualización posterior, de modo que el mapeo sigue teniendo efecto.
