# 🧪 Laboratorio Práctico con Diferentes Niveles — NICS | CyberLab

> **Aviso de uso responsable:** todo lo descrito está orientado a un **entorno de laboratorio autorizado y controlado**. No reutilice procedimientos fuera de un contexto permitido.

---

Perfecto, Cristian. He revisado **todo el contenido real del documento** y el índice original se ha quedado corto respecto a lo que ya está desarrollado (sobre todo ejercicios 3 y 4) y a lo que se anuncia para Level-02.

Aquí tienes un **índice actualizado, coherente y defendible**, alineado con el contenido actual **y preparado para crecer** sin rehacerlo después.

---

Perfecto, Cristian. He revisado **todo el contenido real del documento** y el índice original se ha quedado corto respecto a lo que ya está desarrollado (sobre todo ejercicios 3 y 4) y a lo que se anuncia para Level-02.

Aquí tienes un **índice actualizado, coherente y defendible**, alineado con el contenido actual **y preparado para crecer** sin rehacerlo después.

---

## Índice

* [Introducción](#introducción)

* [Visión general de los escenarios](#visión-general-de-los-escenarios)

  * [Level-01 – Mini SOC: detección y monitorización](#level-01--mini-soc-detección-y-monitorización)
  * [Level-02 – Threat Intelligence y análisis de IOCs (MISP)](#level-02--threat-intelligence-y-análisis-de-iocs-misp)

* [Normas generales del laboratorio](#normas-generales-del-laboratorio)

* [Metodología de trabajo y evidencias](#metodología-de-trabajo-y-evidencias)

---

* [Escenario Level-01 – Mini SOC](#escenario-level-01)

  * [Descripción del escenario](#descripción-del-escenario)
  * [Arquitectura y roles](#arquitectura-y-roles)
  * [Objetivos formativos](#objetivos-formativos)
  * [Requisitos previos y ejecución del escenario](#requisitos-previos-y-ejecución-del-escenario)

---

* [Ejercicio 1 – Snort: detección de tráfico ICMP](#ejercicio-1--snort-detección-de-tráfico-icmp)

* [Ejercicio 2 – Wazuh: agentes, integración de logs y dashboard](#ejercicio-2--wazuh-agentes-integración-de-logs-y-dashboard)

  * [I. Navegación básica del Dashboard](#i-navegación-básica-del-dashboard)
  * [II. Despliegue del agente desde la GUI](#ii-despliegue-del-agente-desde-la-gui-wazuh-manager)
  * [III. Instalación y registro del agente en el nodo Snort](#iii-instalación-y-registro-del-agente-en-el-nodo-snort)
  * [IV. Integración de Snort: lectura de alert_fast.txt](#iv-integración-de-snort-lectura-de-alert_fasttxt)
  * [V. Verificación end-to-end](#v-verificación-end-to-end-generar-alertas-snort-y-verlas-en-wazuh)
  * [VI. Visualización en Wazuh: eventos y Threat Hunting](#vi-visualización-en-wazuh-eventos-y-threat-hunting)
  * [VII. Limpieza: eliminación del agente](#vii-limpieza-eliminación-del-agente-recomendable)
  * [Conclusión técnica del ejercicio](#conclusión-final)

* [Ejercicio 3 – MITRE Caldera: ataque básico y detección en Wazuh](#ejercicio-3--mitre-caldera-ataque-básico-y-detección-en-wazuh)

  * [I. Acceso y verificación inicial en Caldera](#i-acceso-y-verificación-inicial-en-mitre-caldera)
  * [II. Creación de la operación de ataque](#ii-creación-de-la-operación-de-ataque)
  * [III. Ejecución de comandos](#iii-ejecución-de-comandos-desde-caldera)
  * [IV. Análisis de eventos en Wazuh](#iv-análisis-de-eventos-en-wazuh)
  * [V. Correlación ataque → detección](#v-correlación-ataque--detección)


* [Ejercicio 4 – Simulación Mini SOC: escaneo de reconocimiento con Nmap](#ejercicio-4---simulación-mini-soc-escaneo-de-reconocimiento-con-nmap)

  * [I. Verificación del agente víctima](#ii-verificación-del-agente-víctima)
  * [II. Ejecución de reconocimiento sin detección](#iii-ejecución-de-reconocimiento-sin-detección)
  * [III. Activación de reglas de detección](#v-activación-de-reglas-de-detección)
  * [IV. Reejecución del ataque con detección](#vi-reejecución-del-reconocimiento-con-detección)
  * [V. Análisis y validación en Wazuh](#vii-análisis-de-detección-en-wazuh)


* [Ejercicio 5 – Reglas personalizadas y tuning](#ejercicio-5---reglas-personalizadas)

* [Ejercicio 6 – Ataques múltiples y taxonomía MITRE ATT&CK](#ejercicio-6---ataques-múltiples-y-taxonomía)

* [Ejercicio 7 – Defensa, hardening o escalada de privilegios](#ejercicio-7---defensa-o-escalada-de-privilegios)

* [Ejercicio 8 – KPI y métricas de ciberseguridad](#ejercicio-8---kpi-de-ciberseguridad)

---

* [Investigación Opcional](#investigación-opcional) 

---

## Introducción

Este documento recoge los **escenarios prácticos y ejercicios** asociados a los distintos niveles del laboratorio **NICS | CyberLab**. Se persigue guiar la ejecución de prácticas realistas, progresivas y alineadas con el trabajo de un **Security Operations Center (SOC)**.

Cada escenario se apoya en un despliegue automatizado previo y se centra en el uso combinado de herramientas ofensivas y defensivas, reforzando el ciclo **detección → investigación → mejora → reporte**.

---

## Visión general de los escenarios

El laboratorio se estructura en **niveles progresivos**, donde cada nivel amplía o profundiza en los conceptos del anterior.

---

### Level-01 – Mini SOC: detección y monitorización

Nivel orientado a la **aclimatación y familiarización** con herramientas clave de un SOC, mediante un entorno controlado desplegado en OpenStack.

**Nodos principales:**

* **Nodo víctima (IDS):** Snort
* **Nodo monitor (SIEM/XDR):** Wazuh (Manager + Dashboard)
* **Nodo atacante (Adversary Emulation):** MITRE Caldera

En este nivel se trabaja como analista SOC junior, aprendiendo a:

* Detectar tráfico y actividad sospechosa.
* Analizar logs y alertas.
* Correlacionar eventos en un SIEM/XDR.
* Documentar evidencias y conclusiones técnicas.

---

### Level-02 – Threat Intelligence y análisis de IOCs (MISP)

Nivel enfocado en **ciberinteligencia de amenazas**, reutilizando previsiblemente el escenario del Level-01 e incorporando:

* **MIST** — plataforma de Threat Intelligence

**Objetivo principal:**

* Analizar ataques ejecutados en el laboratorio.
* Identificar y extraer **IOCs**.
* Enriquecer y relacionar eventos con inteligencia de amenazas.

---

## Normas generales del laboratorio

Estas normas aplican a todos los niveles:

* Uso exclusivo **educativo** y **en entorno controlado**.
* Documentación obligatoria de cada ejercicio (capturas/logs/conclusiones).
* Prohibida la ejecución de acciones ofensivas fuera del laboratorio autorizado.

---

## Metodología de trabajo y evidencias

Para cada ejercicio, entregue obligatoriamente:

### Evidencias técnicas

* Capturas de terminal.
* Logs relevantes (Snort, Wazuh, sistema).
* Capturas del Dashboard cuando aplique.

Asegure que cada evidencia muestre con claridad:

* Nodo implicado.
* Herramienta utilizada.
* Momento del ejercicio (rango temporal visible cuando sea posible).

### Conclusión técnica

Incluya al final de cada ejercicio:

* Acción realizada.
* Eventos generados/detectados.
* Valor operativo en un SOC real (detección, triage, investigación, respuesta, hardening).

---

## Escenario Level-01

### Descripción del escenario

El escenario **Level-01** despliega un **mini SOC** compuesto por tres instancias interconectadas para simular un flujo realista de ataque, detección y análisis.

**Escenario:** `level-01.sh`

---

### Arquitectura y roles

**Componentes**

* **Snort (víctima):** inspección de tráfico (ICMP, TCP/UDP, firmas).
* **Wazuh (monitor):** ingesta desde agentes, normalización/decodificación, reglas, visualización en Dashboard.
* **Caldera (atacante):** operaciones controladas (agents/abilities) para simular técnicas.

**Flujo recomendado de datos**

1. Genere actividad desde el atacante (ping, nmap, comandos, etc.).
2. Registre alertas en Snort (archivo/console).
3. Ingesten los logs en Wazuh (agente + integración Snort→Wazuh).
4. Investigue en Dashboard y ajuste reglas cuando proceda.

---

### Objetivos formativos

1. Generar telemetría y alertas (Snort).
2. Centralizar y correlacionar eventos (Wazuh).
3. Ejecutar acciones ofensivas controladas y trazables (Caldera).
4. Comprender el ciclo detección → investigación → mejora (reglas) → reporte (KPI).

---

### Requisitos previos y ejecución del escenario

**Requisitos**

* Acceso a OpenStack (proyecto, red, cuotas).
* Clave SSH disponible.
* Security Groups que permitan:

  * SSH (22) desde la IP de administración.
  * Acceso al Dashboard de Wazuh (típicamente 5601/443 según despliegue).
  * Conectividad entre nodos en la red del laboratorio.

**Ejecución del escenario**
Desde el repositorio raíz:

```bash
cd nics-cyberlab/
chmod +x lab/level-01.sh
bash lab/level-01.sh
```

**Acceso a credenciales e IPs**
Visualice el log del escenario:

```bash
cat log/level.log
```

---

## Ejercicio 1 – Snort: detección de tráfico ICMP

### Objetivo

Verificar detección de tráfico ICMP (ping) y generación de alertas en formato rápido (`alert_fast`) en tiempo real.

### Prerrequisitos

* Acceso SSH al **nodo víctima (Snort)**.
* IP de la interfaz de red del nodo Snort (receptora del ping).
* Host con conectividad para ejecutar el ping (nodo atacante o cliente externo).

---

### I. Identificación de interfaz e IP en el nodo Snort

En el **nodo Snort**, ejecute:

```bash
ip a
```

* Identifique la interfaz conectada a la red del laboratorio (por ejemplo, `ens3`).
* Anote la IP asignada (por ejemplo, `10.0.0.X`).

> A partir de aquí se asume `ens3`. Sustituya la interfaz si corresponde.

---

### Terminal 1 (Nodo Snort) — Arranque de Snort capturando tráfico

Inicie Snort en modo captura usando:

* interfaz `ens3`
* configuración `/etc/snort/snort.lua`
* salida rápida `alert_fast`
* logs en `/var/log/snort`

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

**Observación esperada**

* Arranque sin errores.
* Proceso en ejecución (sin devolver prompt).

**Si falla**

* Verifique interfaz, permisos y ruta de configuración.

**Evidencie**

* Capture la terminal con Snort ejecutándose y sin errores.

---

### Terminal 2 (Nodo Snort) — Monitorización de alertas en tiempo real

En otra sesión SSH al mismo nodo, monitorice:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Observación esperada**

* Espera de nuevas líneas.
* Aparición de entradas cuando exista coincidencia de reglas.

> Si el fichero no existe, valide el arranque de Snort y la ruta de logs (`-l /var/log/snort`).

**Evidencie**

* Capture la terminal con `tail -f` activo.

---

### Terminal 3 (Cliente externo o Nodo atacante) — Generación de ICMP (ping)

Ejecute:

```bash
ping -c 4 <IP_tarjeta_snort>
```

Ejemplo:

```bash
ping -c 4 10.0.0.25
```

**Resultado esperado**

* Aparición de alertas ICMP en `alert_fast.txt`.

**Criterio de éxito**

* Snort capturando en Terminal 1.
* Alertas visibles en Terminal 2 al ejecutar ping en Terminal 3.

---

### Evidencia a entregar

Capture pantalla o copie salida de:

* Snort en ejecución (Terminal 1)
* alertas en `alert_fast.txt` (Terminal 2)
* salida del ping (Terminal 3)

---

### Validación si no aparece alerta

* Confirme llegada de ICMP a la interfaz:

```bash
sudo tcpdump -ni ens3 icmp
```

* Confirme escritura de logs:

```bash
ls -lah /var/log/snort/
```

* Confirme reglas ICMP habilitadas según set de reglas instalado.

---

## Ejercicio 2 – Wazuh: agentes, integración de logs y dashboard

### Objetivo

1. Ubicar y utilizar módulos clave del **Dashboard de Wazuh** (agentes, hunting, eventos).
2. Desplegar un **agente** desde la GUI del Manager.
3. Configurar el **Wazuh Agent** (nodo Snort) para ingerir logs de Snort (`alert_fast.txt`).
4. Verificar en el Dashboard la llegada de eventos y documentar evidencias.

---

## I. Navegación básica del Dashboard

> La IP/URL y credenciales del Dashboard se obtienen del despliegue (por ejemplo, `log/level.log`).

### 2.1 Identificación de Endpoints Summary

1. Acceda al Dashboard e inicie sesión.
2. Navegue a: **☰ → Server management → Endpoints Summary**
3. Observe el listado de agentes.

**Evidencie**

* Capture la vista **Endpoints Summary**.

### 2.2 Identificación de Threat Hunting

Ubique: **☰ → Threat Intelligence → Threat Hunting**

No ejecute búsquedas todavía; únicamente localice el módulo.

**Evidencie**

* Capture la pantalla de **Threat Hunting**.

---

## II. Despliegue del agente desde la GUI (Wazuh Manager)

### 2.3 Inicio del asistente de despliegue

1. Acceda a **☰ → Server management → Endpoints Summary**
2. Pulse **+ Deploy new agent**

**Evidencie**

* Capture el inicio del **asistente guiado** de despliegue (“Deploy new agent”).

### 2.4 Completar el asistente y obtener comandos (especificación)

Complete el asistente. Habitualmente se solicitará:

1. **Sistema operativo del endpoint**

   * Seleccione Linux (si el nodo Snort es Linux).

2. **Dirección del Manager**

   * Indique IP/hostname del Wazuh Manager **alcanzable desde el nodo Snort**.

3. **Nombre del agente**

   * Defina un nombre consistente (por ejemplo, `snort-server`).

4. **Grupo (opcional)**

   * Asigne un grupo (por ejemplo, `soc-lab` o `snort-endpoints`).

5. **Bloque de comandos**

   * Obtenga los comandos generados para:

     * instalar `wazuh-agent` (repositorio + paquete)
     * configurar variables básicas (Manager/Nombre)
     * registrar/enrolar el agente
     * iniciar y habilitar el servicio

> **Nota operativa:** la forma exacta del comando varía por versión (instalación por repositorio, script, o enrolamiento). Ejecute exactamente lo generado por el Dashboard.

**Evidencie**

* Capture la pantalla donde se visualicen los **comandos generados**.

---

## III. Instalación y registro del agente en el nodo Snort

### 2.5 Ejecución de comandos del asistente (Nodo Snort)

Conéctese por SSH al **nodo Snort** y ejecute el bloque de comandos generado por el Dashboard.

**Evidencie**

* Capture la salida que muestre instalación/registro sin errores.

### 2.6 Verificación del estado del servicio (Nodo Snort)

```bash
sudo systemctl status wazuh-agent
```

Si no está activo:

```bash
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

**Evidencie**

* Capture `status` mostrando **active (running)**.

### 2.7 Verificación del agente en el Dashboard

Regrese al Dashboard:

* **☰ → Server management → Endpoints Summary**
* Localice el agente por nombre y valide:

  * estado **Active/Connected**
  * “last keep alive” reciente

**Evidencie**

* Capture el agente en estado **Active**.

---

## IV. Integración de Snort: lectura de `alert_fast.txt`

### 2.8 Configuración de ingesta en el agente (Nodo Snort)

> Este apartado puede estar **ya realizado** en el entorno. Proceda así:
> * Si ya existe el bloque `localfile`, **visualice y evidencie** la configuración.
> * Si no existe, **genere uno nuevo** para el agente creado.

Edite la configuración:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Localice la sección:

```xml
<!-- Log analysis -->
```

Añada o verifique:

```xml
<!-- Log analysis -->
  <localfile>
    <log_format>snort-fast</log_format>
    <location>/var/log/snort/alert_fast.txt</location>
  </localfile>
```

**Evidencie**

* Capture el fragmento de `ossec.conf` donde se visualice `<localfile>`.

### 2.9 Reinicio del agente (Nodo Snort)

```bash
sudo systemctl restart wazuh-agent && sudo systemctl status wazuh-agent
```

**Evidencie**

* Capture el `status` tras el reinicio (servicio activo).

---

## V. Verificación end-to-end: generar alertas Snort y verlas en Wazuh

### 2.10 Generación de eventos en Snort (Nodo Snort)

Arranque Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

### 2.11 Visualización de logs de Snort en vivo (Nodo Snort)

En otra terminal:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Evidencie**

* Capture el `tail -f` mostrando entradas nuevas.

### 2.12 Generación de ICMP desde un cliente (externo o nodo atacante)

```bash
ping -c 4 <IP_tarjeta_snort>
```

**Evidencie**

* Capture la salida del `ping`.

---

## VI. Visualización en Wazuh: eventos y Threat Hunting

### 2.13 Acceso a Threat Hunting y selección del agente

En el Dashboard:

1. Acceda a **☰ → Threat Intelligence → Threat Hunting**
2. Seleccione el agente `snort-server` (o el nombre definido)
3. Ajuste el rango temporal a **Last 15 minutes** (amplíe si hubo pausas)

**Evidencie**

* Capture **Threat Hunting** con agente seleccionado y rango temporal visible.

### 2.14 Ruta de “Events” y validación alternativa

Según versión, los eventos también se consultan desde:

* **☰ → Threat Intelligence → Threat Hunting → Events**

**Evidencie**

* Capture la vista **Events/Discover** con eventos listados y rango temporal visible.

### 2.15 Filtrado de eventos relacionados con Snort

En Threat Hunting o Events/Discover, aplique filtros típicos:

* palabra clave: `snort`
* fragmentos del mensaje del log
* filtro por agente/host (cuando exista selector)

**Evidencie**

* Capture la lista de eventos evidenciando que corresponden a Snort.

### 2.16 Revisión del detalle de un evento

Abra un evento y revise:

* timestamp
* agente/host
* mensaje/payload
* campos relevantes (si se muestran)

**Evidencie**

* Capture el detalle del evento.

---

## VII. Limpieza: eliminación del agente (recomendable)

> Realice esta limpieza especialmente si se repetirán despliegues o si se requiere dejar el entorno estable.

En el nodo Wazuh a través del terminal:

```bash
sudo /var/ossec/bin/manage_agents
```

Acciones típicas:

* listar agentes
* seleccionar agente a eliminar
* confirmar eliminación

**Evidencie**

* Capture la pantalla donde se observe la eliminación.

---

## Conclusión final

Redacte una conclusión técnica:

* Integración realizada (agente registrado y activo).
* Log integrado (`/var/log/snort/alert_fast.txt`) y mecanismo de ingesta (`localfile` con `snort-fast`).
* Validación end-to-end (alerta Snort generada por ping y evento visible en Wazuh).
* Utilidad SOC (detección, trazabilidad, triage y base para casos de uso/reglas).

---

## Ejercicio 3 – MITRE Caldera: ataque básico y detección en Wazuh

### Objetivo

Ejecutar una **operación básica de ataque** desde **MITRE Caldera** contra el nodo víctima y verificar si la actividad generada es **detectada y registrada en Wazuh**.

El ejercicio permite comprender el flujo:

> **ataque (Caldera) → ejecución en víctima → telemetría → detección (Wazuh)**

---

### Prerrequisitos

* Acceso al **Dashboard de MITRE Caldera** (nodo atacante).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Agente de Caldera **activo** en el nodo víctima (Snort).
* Agente de Wazuh **instalado y operativo** en el nodo Snort.

Las IPs y credenciales pueden consultarse en:

```bash
cat log/level.log
```

---

## I. Acceso y verificación inicial en MITRE Caldera

### 3.1 Acceso al Dashboard de MITRE Caldera

Desde un navegador, acceda a:

```
http://IP_CALDERA:8888
```

Autentíquese con las credenciales del laboratorio.

**Observación esperada**

* Acceso correcto al Dashboard.
* Visualización del menú lateral (Agents, Operations, Adversaries, etc.).

---

### 3.2 Verificación del agente en Caldera

En el Dashboard de Caldera:

1. Acceda a **Agents**.
2. Identifique el agente correspondiente al **nodo víctima (Snort)**.

**Observación esperada**

* Agente visible.
* Estado **Alive** (activo).

> Si el agente no está activo, **no continúe** con el ejercicio.

---

## II. Creación de la operación de ataque

### 3.3 Creación de una operación básica

Acceda a **Operations** y seleccione **New Operation**.

Configure la operación con los siguientes parámetros:

* **Name:** `XXxx-ataque-basico`
* **Group:** `red` 
* **Adversary:** `Worm`
* **Planner:** `atomic`
* **Run State:** `Run`

Inicie la operación.

**Observación esperada**

* Operación creada correctamente.
* Estado: en ejecución.

---

## III. Ejecución de comandos desde Caldera

### 3.4 Ejecución de comandos

Ejecute las siguientes acciones desde la operación creada:

1. **Comando básico de ejecución** (MITRE T1059):

```bash
whoami
```

2. **Comando con impacto en logs** (simulación de escalada):

```bash
sudo su
```

**Resultado esperado**

* Ambos comandos se ejecutan con estado `SUCCESS`.
* La salida es visible desde Caldera.

> El segundo comando está diseñado para **generar telemetría clara**.

---

## IV. Análisis de eventos en Wazuh

### 3.5 Análisis de telemetría en Wazuh

Acceda al **Dashboard de Wazuh**:

```
https://IP_WAZUH_DASHBOARD
```

☰ → Threat Intelligence → Threat Hunting → Events

Filtre los eventos por:

* `agent.name` → nodo Snort
* Rango temporal → últimos 10 minutos

**Observación esperada**

* Eventos relacionados con:

  * Uso de `sudo`
  * Ejecución de comandos
  * Cambios de privilegio

---

## V. Correlación ataque → detección

### 3.6 Correlación y validación

Identifique al menos una alerta y documente:

* **Regla** que ha generado la alerta (`rule.id` y `rule.description`).
* **Nivel de severidad** (`rule.level`).
  *Es la “criticidad” que asigna Wazuh según la regla que coincide con el evento (rango típico 0–15):*

  * **1–3:** bajo / informativo (actividad común, pero útil para evidenciar).
  * **4–6:** medio (más relevante).
  * **7+:** alto (anomalías, integridad, compliance, etc.).
    *Que sea nivel bajo no significa que “no importe”, solo que es frecuente; en este ejercicio sirve para demostrar que ocurrió (p. ej., `sudo`).*
* **Timestamp** (`timestamp`) del evento/alerta.

**Criterio de éxito**

* La actividad ejecutada desde Caldera es visible en Wazuh.
* Los eventos están correctamente asociados al nodo Snort (`agent.name = snort-server`).

---

### Evidencia a entregar

Documente o capture:

* Agente activo en Caldera (Alive).
* Operación ejecutada con éxito (tasks en SUCCESS).
* Comandos ejecutados (salida visible en Caldera).
* Eventos correspondientes en Wazuh (misma ventana temporal, mostrando `rule.id`, `rule.level`, `timestamp` y `agent.name`).

---

### Validación si no aparece evento en Wazuh

```bash
sudo systemctl status wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log
```

Revise también el rango temporal aplicado en el Dashboard.

---

## Ejercicio 4 - Simulación Mini SOC: escaneo de reconocimiento con Nmap

### Objetivo

Simular un **ataque de reconocimiento** mediante **Nmap (SYN scan)** ejecutado desde **MITRE Caldera** contra el nodo víctima (Snort) y analizar:

1. La **ausencia de detección** cuando las reglas están desactivadas.
2. La **detección correcta** tras activar reglas en **Snort y Wazuh**.

El ejercicio ilustra el flujo completo de un **Mini-SOC**:

> **reconocimiento (Caldera) → ejecución → logs → correlación → alerta (Wazuh)**

---

### Prerrequisitos

* Acceso al el nodo atacante.
* Acceso al **Dashboard de Wazuh**.
* Agente de Wazuh operativo en el nodo Snort.
* IPs y credenciales disponibles en:

```bash
cat log/level.log
```

#### **¡IMPORTANTE!**  
Lance en el nodo snort siempre:  

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```
> ⚠️ **Advertencia:** recuerde que siempre que quiera capturar tráfico tendrá que arrancar la herramienta con el comando previo.

---

## I. Ejecución de reconocimiento SIN detección

### 4.1 Ejecución del escaneo Nmap

Desde el terminal del nodo caldera, ejecute una habilidad de **Command Execution (T1059)** mediante el comando:

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

---

## II. Análisis en Wazuh (sin reglas activas)

Acceda al **Dashboard de Wazuh**.

1. Vaya a **Discover / Security Events**.
2. Filtre por:

   * `agent.name` → nodo Snort
   * Rango temporal → últimos 10 minutos

**Resultado esperado**

* [✖] No aparecen alertas de escaneo
* [✖] No existe correlación de Nmap

El SOC **no detecta el reconocimiento**.

> ⚠️: Asegurese de que el fallo de la detección no haya sido causado por no tener lanzado snort.

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

---

## III. Activación de reglas de detección

### 4.3 Activar regla en Snort

Primeramente pare snort si está arrancado monitoreando ya sea, y posteriormente realice los siguientes pasos.

En el nodo Snort:

```bash
sudo nano /etc/snort/rules/local.rules
```

Descomente:

```bash
alert tcp any any -> any any (
    msg:"Posible TCP SYN scan detectado";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 5, seconds 20;
    sid:1000011;
    rev:3;
)
```

> Explicar porque se descomenta?

Compruebe su funcionmaiento mediante un test:

```bash
# El fichero de configuración de Snort ha cambiando en la versión 3 a snort.lua
sudo snort -T -c /etc/snort/snort.lua
```

Lance de nuevo:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

---

### 4.4 Activar regla en Wazuh

En el nodo Wazuh Manager:

```bash
sudo nano /var/ossec/etc/rules/snort_local_rules.xml
```

Descomente el grupo y la regla:

```xml
#<group name="local,snort,network,scan">

  <!-- ICMP Echo Request -->
  <rule id="600001" level="5">
    <match>ICMP Echo Request detectado</match>
    <description>Snort - ICMP Echo Request detected</description>
  </rule>

  #<!-- TCP SYN Scan -->
  #<rule id="600010" level="8">
    #<match>Posible TCP SYN scan detectado</match>
    #<description>Snort - TCP SYN scan activity detected</description>
  #</rule>

  </rule>
#</group>
```

Reinicie Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

---

## IV. Reejecución del reconocimiento CON detección

Desde Caldera, ejecute **el mismo comando**:

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

---

## V. Análisis de detección en Wazuh

En el Dashboard de Wazuh:

* Filtre por el agente Snort.
* Observe eventos relacionados con:

  * **Nmap TCP SYN scan**
  * Severidad elevada (level 8)

**Resultado esperado**

* [✔] Alerta visible
* [✔] Regla aplicada correctamente
* [✔] Reconocimiento detectado

---

## Ejercicio 5 – Reglas personalizadas en Snort y Wazuh

### Objetivo

Diseñar y probar **reglas personalizadas** en Snort y Wazuh para mejorar la detección de tráfico sospechoso y reducir falsos positivos.

El ejercicio permite comprender el flujo completo de un Mini-SOC:

**tráfico sospechoso controlado (Caldera) → ejecución en víctima (Snort) → telemetría → detección y correlación (Wazuh)**

Se busca que el alumno:

* Ajuste firmas en Snort (ICMP, TCP SYN, Port Knocking).
* Cree reglas personalizadas en Wazuh para correlación de eventos.
* Evalúe la efectividad de la detección y el impacto en falsos positivos.

---

### Prerrequisitos

* Acceso al nodo atacante.
* Acceso al Dashboard de Wazuh (nodo monitor).
* Agente de Wazuh operativo en el nodo Snort.
* IPs y credenciales disponibles:

```bash
cat log/level.log
```

Snort corriendo para capturar tráfico:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

---

## I. Captura de tráfico CON/SIN detección mediante las reglas actuales

### Prueba ICMP

```bash
ping -c 4 <IP_NODO_SNORT>
```

### Prueba TCP SYN (Nmap)

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

## Nuevas reglas personalizadas

### Prueba Port Knocking

Primero en el nodo atacante instale la herramienta de ``hping3``, y luego posteriormnete ejecute de forma consecutiva:

```bash
sudo hping3 -S -p 1001 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1002 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1003 <IP_NODO_SNORT> -c 1
```

> ℹ️ **Recomendable:** crear un script con las 3 líneas, denominado por ejemplo ``h3ping.sh`` y darle permisos de ejecución ``+x``.

**Observación esperada en Wazuh**  

* [✔] Aparecen alertas de ICMP, TCP SYN.  
* [✖] No aparecen alertas de Port Knocking.  
* [⚠] Asegúrese de que Snort esté corriendo para capturar tráfico.  

---

## II. Activación de reglas de detección

### 5.1 Activar reglas en Snort

En el nodo Snort, editar `/etc/snort/rules/local.rules` y configurar reglas personalizadas para poder detectar el Port-Knocking:

```xml
alert icmp any any -> any any (
    msg:"ICMP Echo Request detectado";
    itype:8;
    detection_filter:track by_src, count 3, seconds 20;
    sid:1000010;
    rev:2;
)

alert tcp any any -> any any (
    msg:"Posible TCP SYN scan detectado";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 5, seconds 20;
    sid:1000011;
    rev:3;
)

<!-- Inserte aquí bloque con la nueva regla para Port-Knocking -->
```

> <details>
> <summary><b>ℹ️ Solución:</b></summary>
> alert tcp any any -> any [1001,1002,1003] ( 
> <br>msg:"Posible port knocking detectado";
> <br>flags:S;
> <br>flow:stateless;
> <br>sid:1000022;
> <br>rev:3;
> <br>)
> </details>  

--- 

Comprobar configuración:  

```bash
sudo snort -T -c /etc/snort/snort.lua
```

Lanzar Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

---

### 5.2 Activar reglas en Wazuh

En el nodo Wazuh Manager, editar `/var/ossec/etc/rules/snort_local_rules.xml`:

```xml
<group name="local,snort,network,scan">

  <rule id="600001" level="5">
    <match>ICMP Echo Request detectado</match>
    <description>Snort - ICMP Echo Request detected</description>
  </rule>

  <rule id="600010" level="8">
    <match>Posible TCP SYN scan detectado</match>
    <description>Snort - TCP SYN scan activity detected</description>
  </rule>

  <!-- Inserte aquí bloque con la nueva regla para Port-Knocking -->

</group>
```

> <details>
> <summary><b>ℹ️ Solución:</b></summary>
>
> ```xml
> <rule id="600020" level="9">
> <br><match>Posible port knocking detectado</match>
> <br><description>Snort - Port knocking attempt detected</description>
> <br></rule>
> ```
>
> </details>  

---

Reiniciar Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

---

## III. Reejecución del tráfico CON detección de las reglas finales

Desde Caldera:

**ICMP**

```bash
ping -c 4 <IP_NODO_SNORT>
```

**TCP SYN (Nmap)**

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

**Port Knocking:**

```bash
sudo hping3 -S -p 1001 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1002 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1003 <IP_NODO_SNORT> -c 1
```

Visualice los logs de snort una vez completada la configuración:

``` bash
sudo tail -f /var/log/snort/alert_fast.txt
```

### Resultado esperado en Snort

```
[**] [1:1000010:2] "ICMP Echo Request detectado"
[**] [1:1000011:3] "Posible TCP SYN scan detectado"
[**] [1:1000022:3] "Posible port knocking detectado"
```

---

## IV. Análisis de detección en Wazuh

En el Dashboard de Wazuh:

* Filtre por **agent.name → nodo Snort**
* Observe eventos relacionados con:

| Evento                    | Severidad Wazuh | Observación                  |
| ------------------------- | --------------- | ---------------------------- |
| ICMP Echo Request         | 5               | Ping detectado               |
| TCP SYN scan              | 8               | Escaneo tipo Nmap detectado  |
| Port Knocking (secuencia) | 9               | Secuencia completa detectada |

**Resultado esperado**

* [✔] Alertas visibles.  
* [✔] Reglas aplicadas correctamente.  
* [✔] Correlación de port knocking generada correctamente.  

> ℹ️ **Nota:** En el siguiente ejercicio se profundizará más sobre los niveles de criticidad de los ataques visto y su taxonomía.

---

## V. Conclusiones

* Ajustar la detección en Snort permite detectar actividades sospechosas evitando **alertas innecesarias** (falsos positivos).
* Modificar reglas en Wazuh mejora la **priorización de eventos** y reduce información irrelevante.
* Comparar los registros antes y después de los cambios permite comprobar la mejora del sistema.
* Las **reglas personalizadas** ayudan a reducir ruido y a centrarse en alertas importantes dentro del Mini-SOC.
* Snort analiza el tráfico de red, mientras que Wazuh correlaciona la información para generar **alertas más precisas**.
* Este ejercicio sirve como base para crear y adaptar nuevas reglas en entornos de laboratorio o producción.

---

## Ejercicio 6 - Ataques múltiples y taxonomía

Pendiente de desarrollo detallado. Orientación:

Matriz Enterprise: https://attack.mitre.org/matrices/enterprise/  
Matriz ICS: https://attack.mitre.org/matrices/ics/

* Correlacionar múltiples señales.
* Clasificar eventos y mapear con MITRE ATT&CK.

---

## Ejercicio 7 - Defensa o escalada de privilegios


Pendiente de desarrollo detallado. Orientación:

Matriz D3FEND: https://d3fend.mitre.org/ 

* Analizar señales de hardening/defensa o post-explotación controlada.
* Documentar hipótesis y evidencias.

---

## Ejercicio 8 – Creación de un KPI operativo basado en un ataque real

### Objetivo

Diseñar un **KPI operativo propio** a partir de un ataque observado durante el laboratorio (MITRE Caldera → Snort → Wazuh), de forma que:

* Permita **detectar rápidamente la recurrencia del ataque**.
* Facilite el **triage y la reacción de otro analista SOC**.
* Sirva como **indicador continuo** de riesgo operativo.

Este ejercicio simula una tarea real de un SOC **Level 1 / Level 2**: transformar una detección puntual en un **indicador reutilizable**.

---

### Contexto del ejercicio

Durante los ejercicios anteriores se ha observado un patrón de ataque realista, por ejemplo:

* Ejecución remota de comandos desde Caldera.
* Uso de `sudo` / cambio de privilegios.
* Actividad anómala detectada por reglas de Wazuh.

Este patrón **no se trata como un evento aislado**, sino como un **caso recurrente** que debe ser monitorizado.

---

## I. Selección del ataque base

### 8.1 Identificación del ataque observado

Seleccione **un ataque concreto** ejecutado en el laboratorio.
Ejemplos válidos:

* Uso no habitual de `sudo` desde una sesión remota.
* Ejecución de comandos sospechosos (`whoami`, `id`, `uname`).
* Acceso inicial seguido de escalada de privilegios.

Documente brevemente:

* Nodo afectado.
* Técnica MITRE asociada (ej. T1059, T1548).
* Regla(s) de Wazuh que lo detectaron.

> **Este ataque será la base del KPI.**

---

## II. Definición del KPI operativo

### 8.2 Diseño del KPI

El KPI debe responder a una pregunta **accionable**, por ejemplo:

> “¿Con qué frecuencia se detectan intentos de escalada de privilegios desde accesos remotos?”

Defina el KPI con la siguiente estructura:

* **Nombre del KPI**
* **Descripción**
* **Evento o patrón que mide**
* **Fuente de datos**
* **Umbral operativo**
* **Acción recomendada**

#### Ejemplo de definición

**KPI:**
`Intentos de escalada de privilegios no esperados`

**Descripción:**
Mide el número de eventos donde se detecta uso de `sudo` o cambio de privilegios en nodos que no deberían realizar tareas administrativas.

**Fuente:**
Wazuh – reglas relacionadas con `sudo` (`rule.id` correspondiente).

**Frecuencia de medida:**
Tiempo real / revisión diaria.

---

## III. Implementación del KPI en Wazuh

### 8.3 Identificación del patrón en Wazuh

Acceda al Dashboard:

☰ → Threat Hunting → Events

Filtre por:

* `agent.name`: nodo Snort
* `rule.description` o `full_log` conteniendo `sudo`
* Rango temporal: últimos ejercicios

Verifique que el patrón es **repetible y reconocible**.

---

### 8.4 Definición de umbrales

Defina un umbral simple y claro:

Ejemplo:

* **0–1 eventos / día:** comportamiento esperado.
* **2–3 eventos / día:** revisión manual.
* **>3 eventos / día:** posible incidente → escalar.

Este umbral es parte del KPI y lo convierte en **operativo**, no solo informativo.

---

## IV. KPI orientado a la reacción del SOC

### 8.5 Playbook simplificado asociado al KPI

Documente los pasos que **otro analista** debe seguir cuando el KPI supera el umbral.

Ejemplo:

**Cuando el KPI se activa (>3 eventos):**

1. Verificar el `agent.name` afectado.
2. Comprobar el usuario que ejecuta `sudo`.
3. Revisar si la IP origen es conocida.
4. Correlacionar con:

   * Eventos de autenticación.
   * Actividad previa (ejecución de comandos).
5. Clasificar:

   * Falso positivo.
   * Incidente real.

> Este bloque es clave: convierte el KPI en **tiempo ahorrado**.

---

## V. Validación del KPI con datos reales

### 8.6 Validación en el laboratorio

Utilice los eventos ya generados para:

* Contar cuántas veces se cumple el patrón.
* Ver si el KPI se activaría.
* Evaluar si el umbral es razonable.

Documente:

* Número de eventos detectados.
* Si se habría escalado o no.
* Qué decisión se tomaría.

---

## VI. Reporte para público no técnico

### 8.7 Traducción ejecutiva

Ejemplo de conclusión:

> Se ha definido un indicador que permite detectar de forma temprana intentos de escalada de privilegios en sistemas monitorizados.
>
> Este indicador permite reducir el tiempo de análisis, ya que asocia directamente un patrón de comportamiento con una serie de acciones predefinidas, mejorando la capacidad de respuesta del SOC ante accesos no autorizados.

---

## VII. Evidencias a entregar

* Evento real usado como base del KPI.
* Capturas de filtros en Wazuh.
* Definición del KPI (nombre, umbral, acción).
* Ejemplo de activación del KPI.
* Playbook simplificado de reacción.

---

## VIII. Conclusión técnica

Incluya:

* Valor del KPI en un SOC real.
* Qué problema resuelve.
* Cómo reduce MTTD / MTTR.
* Posibles mejoras futuras (automatización, SOAR).

---


## Investigación Opcional


Actividad opcional orientada a:


* Plugins y nuevas técnicas en MITRE Caldera.
* Nuevos casos de uso de detección.
* Mejoras del entorno Mini SOC (reglas, dashboards, parsers, tuning).


---

###### © NICS LAB — NICS | CyberLab

Proyecto experimental para entornos de laboratorio y formación en ciberseguridad.

