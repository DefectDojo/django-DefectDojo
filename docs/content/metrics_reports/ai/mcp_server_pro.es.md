---
title: Servidor MCP
description: El servidor MCP de DefectDojo te permite usar LLM con DefectDojo Pro
draft: false
audience: pro
weight: 23
aliases:
- /es/en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: las funciones de IA son exclusivas de DefectDojo Pro.</span>

El servidor MCP (Model Context Protocol) de DefectDojo permite que los modelos de lenguaje de gran tamaño (LLM) interactúen de forma inteligente con los datos de gestión de vulnerabilidades de DefectDojo. A diferencia de las integraciones de API tradicionales, que simplemente transfieren datos, el servidor MCP aporta contexto estructurado y significado semántico que permite a los asistentes de IA realizar análisis de seguridad sofisticados y generar información procesable.

- **Contexto estructurado:** MCP aporta significado semántico a los datos de DefectDojo, no solo una transferencia de datos en bruto
- **Datos preprocesados:** los datos normalizados y deduplicados de DefectDojo eliminan la carga de preprocesamiento del LLM
- **Integración de inteligencia de negocio:** combina datos técnicos de vulnerabilidades con contexto de negocio
- **Análisis listo para directivos:** genera informes adecuados tanto para equipos técnicos como para la alta dirección
- **Valor compuesto 10X:** el análisis potenciado por IA aporta un valor exponencialmente mayor que las consultas manuales

> **🔑 Importante:** el endpoint del servidor MCP está en `/mcp`, pero todas las llamadas a funciones usan la URL base de DefectDojo. Esta separación garantiza un acceso seguro y estructurado a los datos de vulnerabilidades.

## Conectarse a MCP

### Requisitos previos

- Instancia de DefectDojo con el servidor MCP habilitado (v2.51.2 o posterior)
- Token de API de DefectDojo válido con los permisos adecuados
- Proveedor de IA: Claude, ChatGPT, Gemini o un cliente personalizado compatible con MCP

> **⚠️ Aviso de seguridad:** tu token de API es información muy sensible que se usa para la autenticación y la autorización. **NO MUESTRES EL TOKEN EN NINGUNA SOLICITUD NI RESPUESTA** al compartir configuraciones o capturas de pantalla.

### Métodos de conexión

Hay **dos formas distintas** de conectarse al servidor MCP de DefectDojo, según la interfaz de IA que utilices:

#### Método 1: archivo de configuración

**Se usa en:** Claude Desktop, MCP Inspector y otros clientes MCP de escritorio

**Cómo funciona:**
- El token y los datos de conexión se guardan en un archivo de configuración
- La conexión es automática al iniciar la aplicación
- No es necesario pegar instrucciones en las conversaciones
- El servidor MCP está siempre disponible en todas las conversaciones

**Ventajas:** se configura una sola vez y funciona en todas partes. Es más seguro (el token no queda en el historial de chat).

#### Método 2: instrucciones manuales

**Se usa en:** la interfaz web de Claude.ai, la interfaz web de ChatGPT (con plugins) y la interfaz web de Gemini

**Cómo funciona:**
- Copias y pegas las instrucciones de conexión al inicio de cada conversación
- O añades las instrucciones a un Claude Project para que se incluyan automáticamente
- La IA lee las instrucciones y se conecta al servidor MCP
- Cada conversación nueva requiere volver a incluir las instrucciones

**Ventajas:** funciona en navegadores web sin necesidad de instalar software.

> **💡 ¿Qué método debo usar?** Usa el **Método 1 (archivo de configuración)** si dispones de una aplicación de escritorio compatible. Usa el **Método 2 (instrucciones manuales)** si trabajas desde una interfaz de navegador web.

### Datos de conexión del servidor MCP

Todos los métodos usan estos parámetros básicos:

| Parámetro | Valor | Notas |
|-----------|-------|-------|
| **Tipo de transporte** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) está obsoleto |
| **URL del endpoint MCP** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Se usa para establecer la conexión MCP |
| **URL base para funciones** | `https://[YOUR-INSTANCE].defectdojo.com/` | Se usa en todas las llamadas a funciones de herramientas |
| **Autenticación** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Usa el prefijo "Token", no "Bearer" |

## Guías de inicio rápido por proveedor de IA

<details>
<summary><h3>🖥️ Claude Desktop (Método 1: archivo de configuración)</h3></summary>

**Paso 1: localiza tu archivo de configuración**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Paso 2: edita el archivo de configuración**

Añade o actualiza la sección `mcpServers` con los datos de tu instancia de DefectDojo:

```json
{
  "mcpServers": {
    "DefectDojo-MCP": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-instance.defectdojo.com/mcp",
        "--header",
        "Authorization: Token YOUR_API_TOKEN"
      ]
    }
  }
}
```

> **⚠️ Importante:** el indicador `--header` con la autenticación es obligatorio. Sustituye `YOUR_API_TOKEN` por tu token de API real de DefectDojo.

**Paso 3: reinicia Claude Desktop**

Cierra y vuelve a abrir Claude Desktop para que los cambios surtan efecto.

**Paso 4: verifica la conexión**

Inicia una conversación nueva y pregunta: `"Can you connect to DefectDojo?"`

Si la conexión se realiza correctamente, Claude confirmará que tiene acceso a las herramientas del servidor MCP de DefectDojo.

> **✅ Listo.** El servidor MCP de DefectDojo ya está disponible en todas las conversaciones. No es necesario pegar instrucciones.

</details>

<details>
<summary><h3>🌐 Interfaz web de Claude.ai (Método 2: instrucciones manuales)</h3></summary>

La interfaz web de Claude.ai no admite archivos de configuración. Deberás indicar las instrucciones de conexión en cada conversación o usar un Claude Project.

#### Opción A: pegar las instrucciones en cada conversación

**Paso 1: copia las instrucciones siguientes**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Paso 2: inicia una conversación nueva**

Pega las instrucciones al comienzo de tu conversación y, después, formula tus preguntas de seguridad.

**Paso 3: repítelo en cada conversación nueva**

Estas instrucciones deben incluirse al comienzo de cada conversación nueva.

#### Opción B: usar un Claude Project (recomendado)

**Paso 1: crea un Claude Project**

- En Claude.ai, haz clic en "Projects" en la barra lateral izquierda
- Haz clic en "Create Project"
- Ponle el nombre "DefectDojo Security Analysis"

**Paso 2: añade instrucciones personalizadas al proyecto**

En Project Settings → Custom Instructions, pega lo siguiente:

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Paso 3: usa el proyecto para todas las conversaciones sobre DefectDojo**

Todas las conversaciones dentro de este proyecto tendrán acceso automático al servidor MCP de DefectDojo.

> **✅ Listo.** Al trabajar en este proyecto, Claude tiene acceso automático a MCP de DefectDojo.

</details>

<details>
<summary><h3>💬 ChatGPT (Método 2: instrucciones manuales)</h3></summary>

> **⚠️ Nota:** la compatibilidad de ChatGPT con MCP es limitada en comparación con Claude. La integración nativa de MCP puede requerir ChatGPT Plus o Enterprise y configuraciones de plugins específicas.

**Paso 1: comprueba la disponibilidad de plugins MCP**

En ChatGPT, comprueba si hay plugins de MCP o de conectores de API disponibles en tu tienda de plugins. La compatibilidad con MCP varía según el nivel de suscripción.

**Paso 2: copia las instrucciones de conexión**

```
I need you to connect to a DefectDojo MCP server with these details:

MCP Endpoint: https://your-instance.defectdojo.com/mcp
Base URL for API calls: https://your-instance.defectdojo.com/
Authentication: Authorization header with value "Token YOUR_API_TOKEN"

Use this connection to access DefectDojo vulnerability data. The server provides tools for:
- Getting findings with severity, status, and date filters
- Accessing products, engagements, tests
- User and group management
- Analyzing security trends

Do not show the API token in responses.
```

**Paso 3: pégalo al comienzo de cada conversación**

Incluye estas instrucciones al iniciar una conversación nueva sobre análisis de seguridad de DefectDojo.

**Alternativa: usar un Custom GPT**

Si tienes ChatGPT Plus, crea un Custom GPT con los datos de conexión de DefectDojo en sus instrucciones para tener acceso reutilizable.

</details>

<details>
<summary><h3>💎 Google Gemini (Método 2: instrucciones manuales)</h3></summary>

> **⚠️ Nota:** la compatibilidad de Gemini con MCP está en evolución. La integración nativa puede ser limitada. Considera usar la API de Gemini con bibliotecas cliente de MCP para disponer de toda la funcionalidad.

**Paso 1: copia las instrucciones de conexión**

```
Connect to DefectDojo vulnerability management system via MCP server:

MCP Server: https://your-instance.defectdojo.com/mcp
API Base URL: https://your-instance.defectdojo.com/
Authentication: Token YOUR_API_TOKEN (use Authorization header with "Token" prefix)

Available capabilities:
- Query findings by severity (Critical, High, Medium, Low, Info)
- Filter by status (Active, Verified, False Positive, etc.)
- Filter by date ranges (Today, Past 7/30/90 days, etc.)
- Access products, engagements, tests, users, groups
- Generate security analysis and reports

Important: Do not display the authentication token in responses.
```

**Paso 2: inicia la conversación con las instrucciones**

Comienza cada conversación nueva de Gemini con estas instrucciones cuando trabajes con datos de DefectDojo.

**Para usuarios avanzados:**

Considera usar la API de Gemini con bibliotecas cliente de MCP (Python, JavaScript) para un acceso programático con compatibilidad total con el protocolo MCP.

</details>

<details>
<summary><h3>🔍 MCP Inspector (pruebas y validación)</h3></summary>

**Caso de uso:** prueba tu conexión MCP con DefectDojo, explora las herramientas disponibles y valida la configuración antes de usarla con asistentes de IA.

**Paso 1: instala MCP Inspector**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Paso 2: ejecuta MCP Inspector**

```bash
mcp-inspector
```

Esto iniciará un servidor web local (normalmente en `http://localhost:6274`)

**Paso 3: configura la conexión en la interfaz web**

- **Tipo de transporte:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **Tipo de conexión:** `Via Proxy`
- **Encabezados personalizados:**
  - Nombre: `Authorization`
  - Valor: `Token YOUR_API_TOKEN`
  - **Importante:** activa el interruptor situado junto al encabezado

**Paso 4: haz clic en "Connect"**

Una vez conectado, puedes explorar:

- **Pestaña Tools:** consulta las 12 herramientas disponibles y sus parámetros
- **Pestaña Prompts:** revisa las plantillas de prompts preconfiguradas
- **Pestaña Resources:** comprueba los recursos de datos disponibles

> **✅ Ideal para:** verificar que tu configuración funciona antes de configurar los asistentes de IA, explorar las capacidades de las herramientas y solucionar problemas de conexión.

</details>

---

> **✅ ¿Conexión correcta?** Una vez conectado mediante cualquiera de los métodos, compruébalo preguntando a tu asistente de IA: `"How many active findings do we have in DefectDojo?"`

---

## Referencia de herramientas disponibles

El servidor MCP de DefectDojo ofrece 12 herramientas para acceder a los datos de vulnerabilidades y analizarlos. Cada herramienta incluye un manejo inteligente de parámetros y devuelve datos estructurados optimizados para el análisis por parte de LLM.

> **💡 Nota sobre parámetros:** todas las herramientas aceptan un parámetro `token` opcional. Si no se proporciona en llamadas individuales, el LLM usará el token de la configuración de conexión.

---

### 🔍 Herramientas de análisis de hallazgos

<details>
<summary><h4>get_findings</h4></summary>

**Descripción:** recupera hallazgos de DefectDojo con funciones de filtrado avanzadas. Es la herramienta más potente y utilizada para el análisis de vulnerabilidades.

**Parámetros:**

**severity** (opcional)
- **Tipo:** array de cadenas
- **Valores:** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Ejemplo:** `["Critical", "High"]`
- **Uso:** filtra los hallazgos por nivel de severidad. Se pueden indicar varios valores para consultas combinadas.

**status** (opcional)
- **Tipo:** array de cadenas
- **Valores:** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Ejemplo:** `["Active", "Verified"]`
- **Uso:** filtra los hallazgos por su estado actual. Usa `Active` para evaluar el riesgo actual.

**date** (opcional)
- **Tipo:** array con un único valor de cadena
- **Valores:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Ejemplo:** `["3 - Past 30 days"]`
- **Uso:** filtra los hallazgos por fecha de detección. Solo se admite un valor.

**limit** (opcional)
- **Tipo:** número
- **Valor predeterminado:** 100
- **Rango:** 1-100
- **Uso:** número de hallazgos que se devuelven. Para obtener solo el recuento, usa 1 y consulta la propiedad count de la respuesta.

**offset** (opcional)
- **Tipo:** número
- **Valor predeterminado:** 0
- **Uso:** desplazamiento de paginación para obtener resultados adicionales.

> **💡 Buena práctica:** en las consultas de evaluación de riesgos, usa siempre `status: ["Active"]` para centrarte en las vulnerabilidades actuales sin resolver en lugar de en datos históricos.

**Ejemplo de consulta:**

**El usuario pregunta:** "Muéstrame todos los hallazgos activos de severidad Crítica y Alta de los últimos 30 días"

**El LLM llama a:**
```
get_findings({
  severity: ["Critical", "High"],
  status: ["Active"],
  date: ["3 - Past 30 days"],
  limit: 100
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**Descripción:** recupera información detallada sobre un hallazgo específico mediante su identificador único.

**Parámetros:**

**finding_id** (obligatorio)
- **Tipo:** número
- **Mínimo:** 1
- **Uso:** el ID único del hallazgo que se desea recuperar.

**Ejemplo de consulta:**

**El usuario pregunta:** "Dame los detalles del hallazgo #1234"

**El LLM llama a:** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 Herramientas de productos y compromisos

<details>
<summary><h4>get_products</h4></summary>

**Descripción:** recupera todos los productos de DefectDojo. Los productos representan las aplicaciones, servicios o sistemas que se someten a pruebas.

**Parámetros:**

**limit** (opcional)
- **Valor predeterminado:** 100
- **Uso:** número máximo de productos que se devuelven.

**offset** (opcional)
- **Valor predeterminado:** 0
- **Uso:** desplazamiento de paginación.

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Descripción:** recupera las categorías de tipo de producto de DefectDojo. Los tipos de producto ayudan a organizar los productos en agrupaciones lógicas.

**Parámetros:** los mismos que `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Descripción:** recupera los compromisos de pruebas de seguridad. Los compromisos representan actividades de prueba específicas o periodos de tiempo para un producto.

**Parámetros:** los mismos que `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Descripción:** recupera los tests de seguridad de DefectDojo. Los tests contienen los resultados de análisis de herramientas de seguridad específicas o de pruebas manuales.

**Parámetros:** los mismos que `get_products`

</details>

---

### 👥 Herramientas de gestión de usuarios y accesos

<details>
<summary><h4>get_users</h4></summary>

**Descripción:** recupera todos los usuarios de DefectDojo para el análisis de partes interesadas y la asignación de responsabilidades.

**Parámetros:**

**limit** (opcional)
- **Valor predeterminado:** 100

**offset** (opcional)
- **Valor predeterminado:** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Descripción:** recupera información detallada sobre un usuario específico.

**Parámetros:**

**user_id** (obligatorio)
- **Tipo:** número
- **Mínimo:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Descripción:** recupera los grupos de usuarios para el análisis de la estructura organizativa y la asignación de permisos.

**Parámetros:** los mismos que `get_users`

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Descripción:** recupera información detallada sobre un grupo específico.

**Parámetros:**

**group_id** (obligatorio)
- **Tipo:** número
- **Mínimo:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Descripción:** recupera todos los miembros de un grupo específico para el análisis de equipos.

**Parámetros:**

**group_id** (obligatorio)
- **Tipo:** número
- **Mínimo:** 1

**limit** (opcional)
- **Valor predeterminado:** 100

**offset** (opcional)
- **Valor predeterminado:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Descripción:** recupera las definiciones de roles de DefectDojo para comprender la estructura de permisos.

**Parámetros:** los mismos que `get_users`

</details>

---

## Prompts preconfigurados

El servidor MCP de DefectDojo incluye prompts preconfigurados que muestran las prácticas recomendadas para escenarios de análisis habituales. Tu asistente de IA puede invocar estos prompts directamente.

### 🛡️ Informe de revisión SAST

**Objetivo:** crear un informe completo que evalúe la eficacia de las herramientas SAST (Static Application Security Testing) a partir de los datos de DefectDojo.

**El análisis generado incluye:**

- Tasas de falsos positivos por herramienta y tipo de vulnerabilidad
- Tiempo medio de corrección por nivel de severidad
- Vulnerabilidades críticas que aparecen varias veces (carencias en la deduplicación)
- Comparación del rendimiento entre equipos de desarrollo
- Recomendaciones para mejorar la configuración de las herramientas
- Carencias de formación identificadas a partir de patrones de vulnerabilidades recurrentes
- Análisis de costes del enfoque de herramientas actual frente al recomendado

**Formato de salida:** informe técnico de evaluación en HTML, adecuado para justificar solicitudes de presupuesto de herramientas de seguridad.

### 📊 Informe del panorama de seguridad

**Objetivo:** crear un informe con formato de panel que ofrezca una visión general del panorama de seguridad a partir de los datos de DefectDojo, adecuado para las reuniones trimestrales del consejo.

**El análisis generado incluye:**

- Tendencias de vulnerabilidades de los últimos 90 días
- Equipos de desarrollo con más hallazgos de severidad crítica o alta
- Exposición al riesgo por producto y tipo de producto
- Las 5 categorías CWE principales que requieren atención inmediata
- Acciones de corrección concretas con análisis de coste-beneficio
- Hoja de ruta a 6 meses para mejorar la postura de seguridad

**Formato de salida:** informe HTML de nivel ejecutivo con elementos visuales, tarjetas de estadísticas y enfoque en el riesgo de negocio.

> **💡 Uso de los prompts:** para invocar un prompt, basta con pedírselo a tu asistente de IA: "Crea un informe de revisión SAST" o "Genera un informe del panorama de seguridad usando datos de DefectDojo"

---

## Ejemplos de casos de uso

### Caso de uso 1: panel de seguridad para directivos

**Escenario:** el CISO necesita métricas de seguridad trimestrales para una presentación al consejo

**Prompt del usuario:**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**Qué ocurre entre bastidores:**

1. `get_findings`: obtiene el recuento total de hallazgos activos
2. `get_findings`: análisis de severidad Crítica y Alta
3. `get_findings`: datos de tendencia de los últimos 90 días
4. `get_products`: distribución de vulnerabilidades por producto
5. `get_engagements`: actividades de prueba recientes

**Resultado generado:** informe HTML de nivel ejecutivo con tendencias de vulnerabilidades, exposición al riesgo por producto, principales categorías CWE, acciones de corrección concretas con ROI y una hoja de ruta de seguridad a 6 meses.

---

### Caso de uso 2: análisis del rendimiento de los equipos de desarrollo

**Escenario:** un responsable de ingeniería quiere saber qué equipos necesitan formación adicional en seguridad

**Prompt del usuario:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**Qué ocurre entre bastidores:**

1. `get_findings`: todos los hallazgos activos
2. `get_products`: vincula los hallazgos con productos y equipos
3. `get_groups`: estructura organizativa de los equipos
4. `get_users`: responsabilidad individual de cada desarrollador

**Análisis entregado:** hallazgos agrupados por equipo, análisis de patrones CWE que muestra errores repetidos, identificación de carencias de formación y recomendaciones de programas de formación en seguridad específicos.

---

### Caso de uso 3: evaluación de la eficacia de las herramientas

**Escenario:** el equipo de seguridad evalúa el ROI de sus herramientas SAST actuales

**Prompt del usuario:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**Qué ocurre entre bastidores:**

1. `get_tests`: todos los tests de seguridad por herramienta
2. `get_findings`: análisis de falsos positivos
3. `get_findings`: hallazgos activos por herramienta
4. `get_findings`: hallazgos cerrados para analizar patrones de corrección

**Análisis entregado:** tasas de falsos positivos por herramienta, tiempo medio de corrección por severidad, análisis de hallazgos duplicados, recomendaciones de configuración de herramientas, carencias de formación y análisis de coste-beneficio de enfoques de herramientas alternativos.

---

### Caso de uso 4: informes de cumplimiento

**Escenario:** preparación de una auditoría SOC 2 que requiere evidencias de la gestión de vulnerabilidades

**Prompt del usuario:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**Qué ocurre entre bastidores:**

1. `get_findings`: hallazgos activos de severidad Crítica o Alta
2. `get_findings`: tendencias de detección desde el inicio del año
3. `get_engagements`: frecuencia y cobertura de las pruebas
4. `get_users`: responsabilidad de la corrección

**Análisis entregado:** procesos de detección y corrección de vulnerabilidades, seguimiento del cumplimiento de los SLA, evidencias de monitorización continua, documentación de responsabilidades y carencias que deben corregirse antes de la auditoría.

---

### Caso de uso 5: priorización de riesgos

**Escenario:** el equipo de seguridad tiene recursos limitados y necesita priorizar las tareas de corrección

**Prompt del usuario:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**Qué ocurre entre bastidores:**

1. `get_findings`: hallazgos activos de severidad Crítica o Alta
2. `get_products`: contexto de criticidad de negocio
3. Análisis de métricas de antigüedad (días desde la detección)
4. Cruce de datos con las puntuaciones EPSS (predicción de explotabilidad)

**Análisis entregado:** lista de vulnerabilidades clasificadas por riesgo que combina severidad, antigüedad, explotabilidad e impacto de negocio. Hoja de ruta de corrección concreta con estimaciones de esfuerzo y la reducción de riesgo esperada.

---


## Prácticas recomendadas y patrones de consulta

### Estrategia de carga progresiva de datos

Tu asistente de IA optimiza el rendimiento siguiendo automáticamente estos patrones de carga de datos:

**1. Empieza con datos resumidos**

Pide recuentos antes de solicitar un análisis detallado:

```
"How many critical and high severity findings do we have?"
```

Tu asistente de IA usará la herramienta `get_findings` con `limit: 1` para obtener el recuento de forma eficiente.

**2. Usa la paginación de forma estratégica**

En conjuntos de datos grandes, tu asistente de IA recorre los resultados por páginas automáticamente:

```
"Analyze all our active vulnerabilities"
```

La IA realizará varias llamadas si es necesario, empezando con límites razonables y aumentándolos según haga falta.

**3. Reutilización eficiente de datos**

Formula preguntas relacionadas de forma consecutiva para evitar consultas redundantes:

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

La IA reutilizará los datos de hallazgos de la primera consulta para el análisis de CWE.

### Estrategias de filtrado inteligente

Diseña tus prompts para aprovechar las potentes funciones de filtrado de DefectDojo:

#### Consultas basadas en la severidad

**Prompt del usuario:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**Entre bastidores:** la IA usa `get_findings` con filtros de severidad y estado

#### Consultas basadas en fechas

**Prompt del usuario:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**Entre bastidores:** la IA aplica el filtro de fecha "Past 30 days" con estado activo

#### Filtrado combinado

**Prompt del usuario:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**Entre bastidores:** la IA combina los filtros de severidad, estado y fecha para un análisis completo

### Análisis cruzado

Tu asistente de IA vincula automáticamente los hallazgos con el contexto organizativo. Basta con formular preguntas completas:

**Prompt del usuario:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**Entre bastidores:** la IA vincula hallazgos → tests → compromisos → productos → usuarios/grupos para obtener el contexto completo

### Análisis de inteligencia de vulnerabilidades

**Análisis de patrones CWE**

**Prompt del usuario:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

La IA agrupará los hallazgos por CWE para identificar patrones recurrentes, necesidades de formación y problemas arquitectónicos.

**Métricas de antigüedad**

**Prompt del usuario:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

La IA calcula el tiempo transcurrido desde la detección y señala los hallazgos que superan los umbrales del SLA.

**Densidad de vulnerabilidades**

**Prompt del usuario:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

La IA calcula los hallazgos por producto y genera puntuaciones de riesgo que combinan severidad y volumen.

### Estándares de mejora de informes

#### Incluye siempre

- **Métricas concretas:** recuentos reales por severidad, no generalizaciones
- **Análisis de CWE:** los principales tipos de vulnerabilidad con sus descripciones
- **Datos de antigüedad:** cuánto tiempo llevan abiertas las vulnerabilidades
- **Recomendaciones accionables:** qué hacer a continuación, con plazos
- **Cálculos de ROI:** coste esperado frente al beneficio de las acciones
- **Métricas de éxito:** cómo medir la mejora

#### Integración de contexto del sector

Compara los hallazgos de DefectDojo con marcos de referencia del sector:

- **OWASP Top 10:** riesgos de seguridad de aplicaciones web
- **SANS Top 25:** las debilidades de software más peligrosas
- **CWE Top 25:** las debilidades más comunes y con mayor impacto
- **Marcos de cumplimiento:** SOC 2, ISO 27001, NIST CSF

## Solución de problemas de MCP

### Lista de comprobación de diagnóstico

Comprueba estos puntos si tienes problemas de conexión:

- ✅ El tipo de transporte es **Streamable HTTP** (no SSE)
- ✅ La URL del endpoint MCP es correcta: `https://[instance].defectdojo.com/mcp`
- ✅ El encabezado Authorization está habilitado (el interruptor está en ON)
- ✅ El formato del token incluye el prefijo `Token`
- ✅ El token es válido y tiene los permisos adecuados
- ✅ La instancia de DefectDojo es accesible (se puede iniciar sesión desde la interfaz web)
- ✅ La conectividad de red permite conexiones HTTPS

### Problemas de conexión habituales

#### ❌ "Connection Error - Check if your MCP server is running"

**Causa:** uso del tipo de transporte SSE (Server-Sent Events), que está obsoleto

**Solución:** cambia el tipo de transporte a `Streamable HTTP`

**Motivo:** el servidor MCP de DefectDojo usa el protocolo moderno Streamable HTTP. SSE está obsoleto y no es compatible.

---

#### ❌ "Authentication Failed" or "401 Unauthorized"

**Causa:** formato incorrecto del encabezado de autenticación o token no válido

**Soluciones:**

1. Comprueba que el valor del encabezado use el prefijo `Token` (no `Bearer`)
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Comprueba que el interruptor del encabezado Authorization esté HABILITADO (en ON)
3. Comprueba que el token siga siendo válido en DefectDojo (Admin → API Tokens)
4. Comprueba que el token tenga los permisos adecuados para acceso de lectura

---

#### ❌ Tool Returns Empty Results

**Posibles causas:**

- Los filtros son demasiado restrictivos (ningún dato coincide con los criterios)
- La instancia de DefectDojo no tiene datos en la categoría solicitada
- Permisos insuficientes del token

**Soluciones:**

1. Prueba primero con una consulta más amplia: `get_findings({ limit: 10 })`
2. Elimina los filtros de uno en uno para identificar cuál es demasiado restrictivo
3. Comprueba los permisos del token en DefectDojo
4. Comprueba si los datos existen directamente en la interfaz de DefectDojo

---

#### ⚠️ Slow Response Times

**Causa:** solicitar demasiados datos a la vez

**Soluciones:**

- Reduce el parámetro `limit` (empieza con 50-100)
- Usa filtros más específicos para reducir el tamaño del conjunto de resultados
- Usa carga progresiva: obtén primero los recuentos y después los detalles
- Implementa la paginación para conjuntos de datos grandes

---
