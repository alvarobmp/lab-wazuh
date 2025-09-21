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

### Paso 1: Preparar la laptop Ubuntu
1. **Instalar y habilitar SSH**:
   - Abre una terminal en Ubuntu y ejecuta:
     ```bash
     sudo apt update
     sudo apt install openssh-server
     sudo systemctl enable ssh
     sudo systemctl start ssh
     ```
   - Verifica que SSH esté funcionando:
     ```bash
     sudo systemctl status ssh
     ```

2. **Configurar el firewall**:
   - Asegúrate de que el firewall permita conexiones SSH:
     ```bash
     sudo ufw allow ssh
     ```

3. **Obtener la IP de Ubuntu**:
   - Anota la IP de Ubuntu ejecutando:
     ```bash
     ip a
     ```
   - Busca la IP en la interfaz de red (por ejemplo, `eth0` o `wlan0`). Será algo como `192.168.1.x`.

### Paso 2: Simular intentos de acceso SSH desde Windows
1. **Abrir PowerShell en Windows**:
   - Haz clic en Inicio, escribe "PowerShell" y ejecútalo como administrador.

2. **Generar intentos fallidos de SSH**:
   - En PowerShell, ejecuta el siguiente comando reemplazando `IP_UBUNTU` con la IP de tu Ubuntu:
     ```powershell
     $ipUbuntu = "IP_UBUNTU"
     $attempts = 5
     for ($i=1; $i -le $attempts; $i++) {
         Write-Host "Intento $i de $attempts"
         ssh usuario_inexistente@$ipUbuntu
         Start-Sleep -Seconds 2
     }
     ```
   - Esto intentará conectarse por SSH 5 veces con un usuario que no existe, generando eventos de fallo.

### Paso 3: Verificar las alertas en Wazuh
1. **Acceder al dashboard de Wazuh**:
   - Abre tu navegador y ve a la URL del dashboard de Wazuh (por ejemplo, `https://IP_WAZUH_SERVER`).
   - Inicia sesión con tus credenciales.

2. **Buscar alertas de movimiento lateral**:
   - En el menú lateral, ve a **Security Events**.
   - Aplica los filtros:
     - `rule.groups:lateral_movement`
     - `rule.id:100202` (para intentos SSH fallidos)
   - Deberías ver alertas con descripción "Multiple SSH failed login attempts from [IP]".

### Paso 4: Verificar la respuesta automática (bloqueo de IP)
1. **Comprobar el bloqueo en el servidor Wazuh**:
   - En el servidor Wazuh (Ubuntu con Wazuh manager), ejecuta:
     ```bash
     sudo iptables -L -n -v | grep DROP
     ```
   - Deberías ver una regla que bloquea la IP de tu Windows.

2. **Probar el bloqueo**:
   - Desde tu Windows, intenta hacer ping al servidor Wazuh:
     ```cmd
     ping IP_WAZUH_SERVER
     ```
   - Si el bloqueo funcionó, el ping fallará.




