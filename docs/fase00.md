# Fase 00 - Laboratorio Wazuh

## 1. Preparación del entorno

-   Se configuró un servidor Ubuntu para el Wazuh Manager.
-   Se instalaron las dependencias necesarias y se habilitó la
    comunicación con los agentes.

## 2. Instalación de Wazuh Manager

-   Se desplegó Wazuh Manager en Ubuntu siguiendo la documentación
    oficial.
-   Se verificó el estado de los servicios con
    `systemctl status wazuh-manager`.

## 3. Instalación de Wazuh Dashboard

-   Se instaló y configuró Wazuh Dashboard (basado en OpenSearch).
-   Se validó el acceso vía navegador web.

## 4. Registro de Agentes

-   Se generó la clave del agente desde el Manager.
-   Se instaló y configuró el agente en Windows.
-   Se validó la conexión con `agent_control -l`.

## 5. Verificación de conectividad

-   Se confirmaron los agentes en estado `Active`.
-   Validación de keep-alive correcto.

## 6. Prueba de reglas base

-   Se verificaron las primeras alertas generadas por las reglas por
    defecto de Wazuh.
-   Eventos visibles en Dashboard.

## 7. Integración Sysmon

-   Instalación de Sysmon en el equipo Windows.

-   Configuración de reglas para captura de procesos, conexiones de red
    y creación de archivos.

-   Validación en el Manager con:

    ``` bash
    sudo /var/ossec/bin/agent_control -i 003
    ```

-   Confirmación en Dashboard de eventos provenientes de Sysmon (FMI).

## 8. Visualización en OpenSearch Dashboard

### 8.1 - Configuración de índice

-   Se validó la existencia del índice `wazuh-alerts-*`.
-   Se usó para consultar los eventos.

### 8.2 - Creación de Dashboard

-   En el menú `Explore > Dashboard > Create new dashboard` se creó un
    dashboard vacío.
-   Se añadieron visualizaciones desde Threat Hunting y búsquedas
    guardadas.

### 8.3 - Visualizaciones con Sysmon

-   Se creó una visualización **Pie chart** con distribución de eventos
    (`count`) usando el índice `wazuh-alerts-*`.
-   Se creó una visualización **Bar chart** (vertical y horizontal)
    filtrando por `rule.groups: "sysmon"`.
-   Se validó la correcta segmentación de eventos.

### 8.4 - Personalización del Dashboard

-   Se agregaron las visualizaciones al dashboard.
-   Se organizaron en cuadrícula.
-   Se guardó el dashboard para consultas futuras.

### 8.5 - Exportación (opcional)

-   No se realizó ya que no era necesario en este laboratorio.

------------------------------------------------------------------------

✅ **Estado de la fase 00**: completada con éxito del punto 1 al 8.
