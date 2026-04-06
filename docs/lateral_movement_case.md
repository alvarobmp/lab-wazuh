# Caso SOC: Movimiento Lateral con Wazuh
**Repositorio:** [lab-wazuh](https://github.com/alvarobmp/lab-wazuh)  
**Autor:** Álvaro Martínez  
**Fecha:** 2026-04-06  
**Estado:** Resuelto ✅

---

## Índice
1. [Objetivo del caso](#1-objetivo-del-caso)
2. [Técnicas MITRE ATT&CK](#2-técnicas-mitre-attck)
3. [Arquitectura del lab](#3-arquitectura-del-lab)
4. [Configuración del entorno](#4-configuración-del-entorno)
5. [Simulación: PsExec (T1021.002)](#5-simulación-psexec-t1021002)
6. [Simulación: Pass-the-Hash con Mimikatz (T1550.002)](#6-simulación-pass-the-hash-con-mimikatz-t1550002)
7. [Alertas detectadas por Wazuh](#7-alertas-detectadas-por-wazuh)
8. [IOCs documentados](#8-iocs-documentados)
9. [Errores encontrados y soluciones](#9-errores-encontrados-y-soluciones)
10. [Conclusiones y recomendaciones](#10-conclusiones-y-recomendaciones)

---

## 1. Objetivo del caso

Simular y detectar un ataque de movimiento lateral en un entorno Windows, usando herramientas reales empleadas por atacantes reales. El objetivo es validar que Wazuh SIEM detecta correctamente las técnicas MITRE ATT&CK involucradas y genera alertas accionables para el analista SOC.

---

## 2. Técnicas MITRE ATT&CK

| ID | Técnica | Herramienta usada | Descripción |
|---|---|---|---|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec | Ejecución remota de comandos via SMB instalando servicio PSEXESVC |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Mimikatz | Robo de hash NTLM desde lsass.exe para autenticación sin contraseña |
| T1003 | OS Credential Dumping | Mimikatz (sekurlsa) | Extracción de credenciales activas desde memoria del proceso lsass.exe |
| T1569.002 | System Services: Service Execution | PsExec | Instalación de servicio remoto PSEXESVC en el endpoint víctima |

---

## 3. Arquitectura del lab

```
┌─────────────────────────────────┐
│  Ubuntu Server 20.04 LTS        │
│  IP: 192.168.100.17             │
│  - Wazuh Manager                │
│  - Wazuh Indexer (OpenSearch)   │
│  - Wazuh Dashboard              │
└────────────────┬────────────────┘
                 │ TCP 1514
┌────────────────▼────────────────┐
│  Windows 10 (EP200301)          │
│  - Wazuh Agent                  │
│  - Sysmon (32-bit)              │
│  Usuarios: hogar, martinez      │
└─────────────────────────────────┘
```

---

## 4. Configuración del entorno

### 4.1 Sysmon en el agente Windows

Sysmon instalado como servicio de 32-bit con nombre `Sysmon` (no `Sysmon64`).

Verificación:
```powershell
Get-Service | Where-Object {$_.Name -like "*sysmon*"}
# Status: Running | Name: Sysmon
```

### 4.2 Configuración del agente Wazuh (ossec.conf)

Bloque agregado en `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### 4.3 Habilitar archivado de logs en el Manager

Por defecto deshabilitado en Wazuh. Habilitado con:

```bash
sudo sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' /var/ossec/etc/ossec.conf
sudo sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

### 4.4 Reglas personalizadas de detección

Agregadas en `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="lateral_movement,windows,">

  <!-- Detecta PsExec usado para movimiento lateral via SMB -->
  <rule id="110004" level="12">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID" type="pcre2">17|18</field>
    <field name="win.eventdata.PipeName" type="pcre2">\\PSEXESVC</field>
    <options>no_full_log</options>
    <description>T1021.002 - PsExec lanzado para movimiento lateral</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
  </rule>

  <!-- Detecta Pass-the-Hash via Mimikatz usando sekurlsa -->
  <rule id="110005" level="14">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID" type="pcre2">10</field>
    <field name="win.eventdata.TargetImage" type="pcre2">lsass.exe</field>
    <options>no_full_log</options>
    <description>T1550.002 - Acceso a lsass.exe detectado (posible Pass-the-Hash)</description>
    <mitre>
      <id>T1550.002</id>
    </mitre>
  </rule>

</group>
```

Validación de sintaxis:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
# Sin output = configuración correcta
```

---

## 5. Simulación: PsExec (T1021.002)

### Herramienta
PsTools v2.43 — descargado desde Microsoft Sysinternals (gratuito).

### Pasos ejecutados

```powershell
cd C:\Tools\PSTools\
.\PsExec.exe \\127.0.0.1 cmd
```

### Resultado
PsExec instaló el servicio `PSEXESVC` y abrió una shell remota bajo `NT AUTHORITY\SYSTEM`.

### Evidencia en logs

```
win.eventdata.targetFilename: C:\Windows\PSEXESVC.exe
Rule: 92307 (level 3) -> 'Evidence of new service creation found in registry
  under HKLM\System\CurrentControlSet\Services\PSEXESVC\ImagePath'
win.eventdata.image: C:\Tools\PSTools\PsExec.exe
ParentImage: C:\Windows\PSEXESVC.exe
ParentUser: NT AUTHORITY\SYSTEM
```

### Timeline del ataque

| Timestamp (UTC) | Evento | Event ID Sysmon |
|---|---|---|
| 2026-04-06T00:17:16 | Servicio PSEXESVC instalado en registry | 13 (SetValue) |
| 2026-04-06T00:17:17 | PsExec conectó via TCP 127.0.0.1:135 | 3 (Network connection) |
| 2026-04-06T00:22:07 | cmd.exe creado hijo de PSEXESVC.exe | 1 (Process Create) |

---

## 6. Simulación: Pass-the-Hash con Mimikatz (T1550.002)

### Herramienta
Mimikatz v2.x — descargado desde ParrotSec GitHub (gratuito).

### Preparación
Windows Defender deshabilitado temporalmente:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Rehabilitar al terminar:
Set-MpPreference -DisableRealtimeMonitoring $false
```

### Pasos ejecutados

```
cd C:\Tools\Mimikatz\mimikatz-master\x64\
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

### Credenciales capturadas (IOCs)

| Campo | Valor |
|---|---|
| Usuario comprometido | `hogar` / `martinez` |
| Dominio | EP200301 (workgroup) |
| Hash NTLM | `7ce21f17c0aee7fb9ceba532d0546ad6` |
| Hash SHA1 | `139f69c93c042496a8e958ec5930662c6cccafbf` |
| Observación | Ambas cuentas comparten el mismo hash NTLM → misma contraseña |

### Evidencia en logs

```
Rule: 92900 (level 12) -> 'Lsass process was accessed by
  C:\Tools\Mimikatz\mimikatz-master\x64\mimikatz.exe
  with read permissions, possible credential dump'

SourceImage: C:\Tools\Mimikatz\mimikatz-master\x64\mimikatz.exe
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
RuleName: technique_id=T1003,technique_name=Credential Dumping
SourceUser: EP200301\hogar
TargetUser: NT AUTHORITY\SYSTEM
```

---

## 7. Alertas detectadas por Wazuh

### Dashboard - Threat Hunting (filtro aplicado)
```
agent.name: EP200301 AND (rule.id: 92900 OR rule.id: 92307 OR rule.id: 110004 OR rule.id: 110005)
```

| Métrica | Valor |
|---|---|
| Total alertas generadas | 55 |
| Alertas nivel 12 o superior | 1 |
| Top MITRE ATT&CKs detectados | Windows Service, LSASS Memory |
| Agente afectado | EP200301 |
| Pico de actividad | 16:00 - 17:00 hrs (hora local) |

### Reglas disparadas

| Regla ID | Nivel | Descripción | Fuente |
|---|---|---|---|
| 92307 | 3 | Nuevo servicio PSEXESVC creado en registry | Nativa Wazuh |
| 92900 | 12 | lsass.exe accedido por mimikatz.exe | Nativa Wazuh |
| 110004 | 12 | T1021.002 - PsExec movimiento lateral | Personalizada |
| 110005 | 14 | T1550.002 - Acceso a lsass.exe | Personalizada |

---

## 8. IOCs documentados

| Tipo | Valor | Técnica |
|---|---|---|
| Archivo | `C:\Windows\PSEXESVC.exe` | T1569.002 |
| Archivo | `C:\Tools\PSTools\PsExec.exe` | T1021.002 |
| Archivo | `C:\Tools\Mimikatz\mimikatz-master\x64\mimikatz.exe` | T1003 |
| Registry | `HKLM\System\CurrentControlSet\Services\PSEXESVC\ImagePath` | T1569.002 |
| Hash NTLM | `7ce21f17c0aee7fb9ceba532d0546ad6` | T1550.002 |
| Hash SHA1 | `139f69c93c042496a8e958ec5930662c6cccafbf` | T1550.002 |
| Proceso | `lsass.exe` accedido con permisos `0x1010` | T1003 |
| Red | `127.0.0.1:50311 → 127.0.0.1:135` (TCP) | T1021.002 |
| Usuario atacante | `EP200301\hogar` | — |
| Cuenta comprometida | `EP200301\martinez` | — |

---

## 9. Errores encontrados y soluciones

### Error 1 — Sysmon64 no encontrado
**Comando ejecutado:** `Get-Service Sysmon64`  
**Error:** servicio no existe  
**Causa:** Sysmon instalado en versión 32-bit  
**Solución:** Usar `Get-Service | Where-Object {$_.Name -like "*sysmon*"}` para detectar el nombre real del servicio

---

### Error 2 — archives.log no generaba output
**Comando ejecutado:** `sudo tail -f /var/ossec/logs/archives/archives.log | grep -i sysmon`  
**Error:** Sin output aunque el agente enviaba logs  
**Causa:** `logall` y `logall_json` deshabilitados por defecto en Wazuh  
**Solución:**
```bash
sudo sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' /var/ossec/etc/ossec.conf
sudo sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

---

### Error 3 — wazuh-logtest -t no reconocido
**Comando ejecutado:** `sudo /var/ossec/bin/wazuh-logtest -t`  
**Error:** `unrecognized arguments: -t`  
**Causa:** En Wazuh v4.12 el flag `-t` fue eliminado de wazuh-logtest  
**Solución:** Usar `sudo /var/ossec/bin/wazuh-analysisd -t` para validar sintaxis de reglas (sin output = configuración correcta)

---

### Error 4 — ossec-logtest y ossec-analysisd no encontrados
**Comandos ejecutados:** `ossec-logtest -t` / `ossec-analysisd -t`  
**Error:** `command not found`  
**Causa:** En Wazuh v4.x los binarios fueron renombrados con prefijo `wazuh-`  
**Solución:** Usar `wazuh-analysisd` en lugar de `ossec-analysisd`

---

## 10. Conclusiones y recomendaciones

### Lo que demostró este lab

1. Wazuh detecta movimiento lateral con PsExec sin configuración adicional via reglas nativas (92307).
2. El acceso a `lsass.exe` por Mimikatz genera alerta nivel 12 automáticamente (regla 92900).
3. El mapeo MITRE ATT&CK en el dashboard (`Windows Service` + `LSASS Memory`) es accionable para triage inmediato.
4. Dos cuentas con el mismo hash NTLM representan un riesgo real de movimiento lateral masivo en redes con más equipos.

### Recomendaciones para el cliente

| Recomendación | Prioridad |
|---|---|
| Habilitar Credential Guard en Windows 10/11 para proteger lsass.exe | Alta |
| Implementar política de contraseñas únicas por equipo (evitar hash reutilizado) | Alta |
| Restringir uso de PsExec via AppLocker o reglas de firewall interno | Media |
| Activar alertas por email para reglas nivel 12 o superior en Wazuh | Media |
| Rotar credenciales de cuentas `hogar` y `martinez` inmediatamente | Alta |

---

*Documento generado como evidencia de lab SOC — uso educativo en entorno controlado.*  
*No ejecutar estas técnicas en sistemas sin autorización explícita.*
