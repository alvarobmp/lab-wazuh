# Paso 3: Implementación del Caso 2 - Detección de Movimiento Lateral

## Objetivo
Configurar reglas personalizadas y scripts de respuesta automática para detectar y responder a intentos de movimiento lateral.

## Acciones a Realizar

### 3.1 Crear reglas personalizadas para movimiento lateral

1. En el servidor Wazuh, edita el archivo de reglas locales:
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

2. Añade las siguientes reglas (dentro del grupo existente o crea uno nuevo):
```xml
<group name="lateral_movement,">
  <rule id="100200" level="10">
    <if_sid>61599</if_sid>
    <field name="win.eventdata.logonType">3</field>
    <same_source_ip>5m</same_source_ip>
    <description>Multiple lateral movement attempts from $(srcip)</description>
    <mitre>
      <id>T1021</id>
    </mitre>
  </rule>

  <rule id="100201" level="8">
    <if_sid>61599</if_sid>
    <field name="win.eventdata.logonType">3</field>
    <field name="win.eventdata.status">0xc000006d</field>
    <description>Failed lateral movement attempt (invalid credentials) from $(srcip)</description>
    <mitre>
      <id>T1021</id>
    </mitre>
  </rule>
</group>
```

3. Guarda el archivo y copia las reglas actualizadas a tu repositorio local:
```bash
cp /var/ossec/etc/rules/local_rules.xml ~/lab-wazuh/configs/rules/
```

### 3.2 Crear script de respuesta automática para bloquear IPs

1. Crea el script `block-ip.py`:
```bash
sudo nano /var/ossec/etc/scripts/block-ip.py
```

2. Pega el siguiente contenido:
```python
#!/usr/bin/env python3
import json
import subprocess
import sys

def block_ip(ip_address):
    """Bloquear IP en firewall usando iptables"""
    try:
        # Añadir regla para bloquear la IP
        subprocess.run(f"iptables -A INPUT -s {ip_address} -j DROP", shell=True, check=True)
        print(f"IP {ip_address} bloqueada en el firewall")
    except subprocess.CalledProcessError as e:
        print(f"Error al bloquear IP: {e}")

def main():
    try:
        # Leer la alerta de Wazuh
        alert = json.loads(sys.stdin.read())
        # Extraer la IP origen de la alerta
        src_ip = alert["data"]["srcip"]
    except KeyError as e:
        print(f"Error al obtener la IP: {e}")
        return

    # Bloquear la IP
    block_ip(src_ip)

if __name__ == "__main__":
    main()
```

3. Haz el script ejecutable:
```bash
sudo chmod +x /var/ossec/etc/scripts/block-ip.py
```

4. Copia el script a tu repositorio local:
```bash
cp /var/ossec/etc/scripts/block-ip.py ~/lab-wazuh/configs/scripts/
```

### 3.3 Configurar respuesta automática en Wazuh

1. Edita la configuración de Wazuh:
```bash
sudo nano /var/ossec/etc/ossec.conf
```

2. Añade dentro de `<ossec_config>`:
```xml
<command>
  <name>block-ip</name>
  <executable>block-ip.py</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>100200,100201</rules_id>
</active-response>
```

3. Reinicia Wazuh:
```bash
sudo systemctl restart wazuh-manager
```

### 3.4 Probar la detección

1. En el Windows 10, intenta acceder a otro sistema (puede ser un intento fallido de acceso por red).
2. También puedes simular múltiples intentos de acceso desde una misma IP a diferentes usuarios.
3. Verifica las alertas en el dashboard de Wazuh.

### 3.5 Documentar y subir evidencias

1. Captura pantallas de las alertas generadas.
2. Guarda las imágenes en `lab-wazuh/images/lateral_movement/`.
3. Actualiza el README.md con la descripción del caso de uso.
4. Sube los cambios a GitHub:
```bash
git add .
git commit -m "Implementación caso movimiento lateral"
git push origin main
```

## Evidencia
- Capturas de pantalla de las alertas en el dashboard.
- Archivos de reglas y scripts en el repositorio.
- Commit en GitHub con los cambios.

---

Una vez que hayas completado este paso, avísame para continuar con el tercer caso de uso.
