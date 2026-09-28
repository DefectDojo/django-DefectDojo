---
title: Definiciones de Estado de Hallazgo
description: 'Una referencia rápida a los estados de Hallazgo: Abierto, Verificado,
  Aceptado..'
weight: 2
aliases:
- /es/en/working_with_findings/findings_workflows/finding_status_definitions
---

Cada Hallazgo creado en DefectDojo tiene un Estado que comunica información relevante. Los estados ayudan a su equipo a hacer seguimiento de su progreso en la resolución de problemas.

Cada estado de Hallazgo tiene un significado específico según el contexto, que deberá ser definido por su propio equipo. Estas son nuestras sugerencias, pero el uso de su equipo puede variar.

Tenga en cuenta que Abierto/Cerrado no son tipos de Estado **explícitos** para los Hallazgos.  Ciertos aspectos de la interfaz clásica (la tabla "Todos los Hallazgos abiertos", por ejemplo) pueden hacer referencia a Hallazgos Abiertos o Cerrados: esto funciona como un término genérico para

* Hallazgos Activos y/o Verificados, en el caso de "Hallazgos abiertos"
* Hallazgos Inactivos y/o con Riesgo aceptado, En revisión, Fuera de alcance, Falso positivo, en el caso de "Hallazgos cerrados"

## **Estados de Hallazgo abierto**

Una vez que un Hallazgo está **Activo**, se etiquetará como un Hallazgo **Abierto**, independientemente de si ha sido **Verificado.**

Los Hallazgos abiertos se pueden ver desde la vista **Hallazgos \> Hallazgos abiertos** de DefectDojo.

### **Hallazgos Activos**

‘Este Hallazgo ha sido descubierto por una herramienta de escaneo.’

De forma predeterminada, cualquier Hallazgo nuevo creado en DefectDojo se etiquetará como **Activo**. Activo en este caso significa ‘este es un Hallazgo nuevo que DefectDojo no ha registrado en una importación anterior’. Si un Hallazgo ha sido Mitigado en el pasado, pero vuelve a aparecer en un escaneo futuro, el estado de ese Hallazgo se reabrirá para reflejar que la vulnerabilidad ha regresado.

### **Hallazgos Verificados**

‘Nuestro equipo ha confirmado que este Hallazgo existe.’

El hecho de que una herramienta registre un problema no significa necesariamente que el Hallazgo requiera atención de ingeniería. Por lo tanto, los Hallazgos nuevos también se etiquetan como **No verificados** de forma predeterminada. 

Si puede confirmar que el Hallazgo realmente existe, puede marcarlo como **Verificado**.

Ciertas funciones de DefectDojo requieren que los Hallazgos estén Activos y Verificados.  Si no necesita verificar manualmente cada Hallazgo, puede desactivar el requisito de Verificado para alguna o todas estas funciones desde la página **Configuración del sistema** (**interfaz clásica: Configuration > System Settings**, **interfaz Pro: Settings > System > System Settings**).

![image](images/verified_status_toggle.png)

Estos Estados Verificados son necesarios para

* Enviar problemas a Jira
* Aplicar Calificaciones a los Productos
* Calcular Métricas

## **Estados de Hallazgo cerrado**

'La Vulnerabilidad registrada aquí ya no está activa’.

Una vez que se completa el trabajo sobre un Hallazgo, puede Cerrarlo manualmente desde la opción Cerrar Hallazgos. Alternativamente, si se vuelve a importar un escaneo a DefectDojo que no contiene un Hallazgo previamente registrado, ese Hallazgo previamente registrado se cerrará automáticamente.

## **Inactivo**

‘Este Hallazgo fue descubierto anteriormente, pero fue mitigado o no requiere atención inmediata.’

Si un Hallazgo se marca como Inactivo, significa que el problema actualmente no tiene impacto en el entorno del software y no necesita abordarse. Este estado no significa necesariamente que el problema se haya resuelto, ya que las Aceptaciones de riesgo activas también etiquetan a los Hallazgos como Inactivos.

### **En revisión**

‘He enviado este Hallazgo a uno o más miembros del equipo para que lo revisen.’

Cuando un Hallazgo está En revisión, necesita que un miembro del equipo lo revise. Puede poner un Hallazgo en revisión seleccionando **Solicitar revisión de pares** en el menú desplegable del Hallazgo.

![image](images/Finding_Status_Definitions.png)

### **Riesgo aceptado**

‘Nuestro equipo ha evaluado el riesgo asociado con este Hallazgo, y hemos acordado que podemos retrasar su corrección de forma segura.’

Los Hallazgos no siempre se pueden remediar o abordar por diversos motivos. Puede agregar una Aceptación de riesgo a un Hallazgo con la opción Agregar Aceptación de riesgo. Las Aceptaciones de riesgo le permiten subir archivos e ingresar notas para respaldar una decisión de Aceptación de riesgo.

Las Aceptaciones de riesgo tienen fechas de vencimiento, momento en el cual puede reevaluar el impacto del Hallazgo y decidir qué hacer a continuación.

Para obtener más información sobre las Aceptaciones de riesgo, consulte nuestra [Guía](/triage_findings/findings_workflows/os__risk_acceptance/).

### **Fuera de alcance**

‘Este Hallazgo fue descubierto por nuestra herramienta de escaneo, pero detectar este tipo de vulnerabilidad no era el objetivo directo de nuestro test.’

Cuando marca un Hallazgo como Fuera de alcance, está indicando que no es directamente relevante para el Compromiso o Test en el que está contenido.

Si tiene un esfuerzo de testing y remediación relacionado con un aspecto específico de su software, puede usar este Estado para indicar que este Hallazgo no forma parte de ese esfuerzo.

### **Falso positivo**

‘Este Hallazgo fue descubierto por nuestra herramienta de escaneo, pero después de revisar el Hallazgo descubrimos que la vulnerabilidad reportada no existe.’

Una vez que haya revisado un Hallazgo, puede descubrir que la vulnerabilidad reportada en realidad no existe. El estado Falso positivo se mantendrá en las reimportaciones y evitará que los hallazgos coincidentes se abran o cierren, lo que ayuda a reducir el ruido.  

Si una herramienta de escaneo diferente encuentra un Hallazgo similar, no se registrará como Falso positivo. DefectDojo solo puede comparar Hallazgos dentro de la misma herramienta para determinar si un Hallazgo ya ha sido registrado.

## Severidad vs. Riesgo
La Severidad refleja el impacto técnico de un problema si se explota. El Riesgo refleja la urgencia comercial y la respuesta requerida, considerando el contexto, como la exposición, la explotabilidad, los controles compensatorios y el impacto operativo.


## Definiciones de Nivel de riesgo
### Urgente
Un hallazgo que representa un riesgo comercial inmediato e inaceptable.

Alta probabilidad de explotación, o explotación activa observada
Exposición directa de sistemas críticos, datos sensibles o entornos de clientes
Controles compensatorios limitados o inexistentes
No actuar podría resultar en una grave interrupción del negocio, impacto regulatorio o daño a la reputación

Acción esperada: respuesta inmediata SLA típico: remediación de emergencia


### Requiere acción
Un hallazgo que representa un riesgo claro y accionable que requiere remediación o mitigación oportuna.

Existe una ruta de ataque realista
El activo afectado está expuesto, es crítico para el negocio o de cara al cliente
Los controles compensatorios son débiles, están ausentes o no verificados
La explotación resultaría en un impacto medible en el negocio, la seguridad o el cumplimiento

Acción esperada: se requiere remediación o mitigación activa SLA típico: ventana de remediación a corto plazo


### Riesgo medio
Un hallazgo que presenta un nivel moderado de riesgo comercial y debe remediarse en un plazo planificado.

Podría producirse un impacto significativo si se explota
Existe cierta exposición, pero la explotación requiere condiciones o privilegios específicos
Puede afectar indirectamente a sistemas de producción o datos de clientes
A menudo se alinea con problemas de severidad media o alta sin explotabilidad inmediata

Acción esperada: remediación priorizada SLA típico: ventana de remediación planificada


### Riesgo bajo
Un hallazgo que presenta un impacto comercial mínimo y no requiere acción inmediata.

Sin explotación conocida en el mundo real
Exposición limitada o inexistente (por ejemplo, sistemas internos, no productivos, con controles compensatorios sólidos)
La remediación se puede abordar como parte de los ciclos normales de desarrollo o mantenimiento
A menudo son hallazgos informativos o de baja severidad, pero pueden incluir problemas de mayor severidad que estén bien mitigados

Acción esperada: seguimiento y abordaje oportunista SLA típico: mejor esfuerzo / backlog
