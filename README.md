# 🛡️ Laboratorio Wazuh SIEM - Entorno de Operaciones de Seguridad (SOC)

Este proyecto es un laboratorio de infraestructura de seguridad implementado desde cero en hardware físico. Su objetivo es demostrar habilidades prácticas en el despliegue, configuración y operación de un **Stack SIEM (Wazuh)** para la monitorización proactiva, detección de amenazas y respuesta a incidentes, simulando un entorno de Security Operations Center (SOC).

**🔗 Enlace al Caso de Estudio:** [Análisis de Incidente Simulado](./INCIDENTE_SIMULADO.md)

## 🎯 Objetivos del Proyecto
*   Dominar la arquitectura e implementación de un stack SIEM completo (Wazuh Manager, Indexer, Dashboard).
*   Configurar y desplegar agentes multi-plataforma (Linux, Windows) para la recolección centralizada de logs.
*   Implementar y probar casos de uso clave de un SOC:
    *   **File Integrity Monitoring (FIM):** Detección de cambios no autorizados en archivos críticos.
    *   **Detección de Amenazas:** Creación y prueba de reglas personalizadas para identificar actividad maliciosa.
    *   **Análisis Forense Básico:** Investigación de eventos usando logs de Sysmon (creación de procesos, conexiones de red, persistencia).
*   Desarrollar dashboards para la visualización y correlación de eventos de seguridad.

## 🏗️ Arquitectura & Tecnologías

Servidor SIEM- Ubuntu Server 20.04 LTS
       **Wazuh Manager
       **Wazuh Indexer (OpenSearch)
       **Wazuh Dashboard

Agentes (Endpoints Monitoreados)
       **Windows 10 + Wazuh Agent + Sysmon
