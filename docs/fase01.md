Implementación del Caso 1 - Detección y Respuesta a Ransomware

### Objetivo
Configurar reglas personalizadas, scripts de respuesta automática e integración con VirusTotal para detectar y responder a actividades de ransomware.

### Acciones a Realizar

#### 2.1 Crear reglas personalizadas
1. En el servidor Wazuh, edita el archivo de reglas locales:
   ```bash
   sudo nano /var/ossec/etc/rules/local_rules.xml
   ```

2. Añade las reglas para ransomware (dentro de la etiqueta `<group name="syslog,">` o crea un nuevo grupo):
   ```xml
	<group name="ransomware,">
	  <rule id="100102" level="12">
		<if_sid>554</if_sid>
		<field name="file">\.encrypted$|\.locked$|\.crypto$|\.ransom$</field>
		<description>Possible ransomware activity detected: $(file)</description>
		<mitre>
		  <id>T1486</id>
		</mitre>
	  </rule>

	  <rule id="100103" level="10">
		<if_sid>61603</if_sid>
		<field name="win.eventdata.destination">\.encrypted$|\.locked$|\.crypto$|\.ransom$</field>
		<description>Possible ransomware file creation: $(win.eventdata.destination)</description>
		<mitre>
		  <id>T1486</id>
		</mitre>
	  </rule>
	</group>
   ```

3. Guarda el archivo y copia estas reglas a tu repositorio local:
   ```bash
   cp /var/ossec/etc/rules/local_rules.xml ~/lab-wazuh/configs/rules/
   ```

#### 2.2 Crear script de respuesta automática
1. Crea el directorio para scripts si no existe:
   ```bash
   sudo mkdir -p /var/ossec/etc/scripts
   ```

2. Crea el script `ransomware-response.py`:
   ```bash
   sudo nano /var/ossec/etc/scripts/ransomware-response.py
   ```

3. Pega el siguiente contenido (ajusta la API key de VirusTotal):
   ```python
   #!/usr/bin/env python3
   import json
   import requests
   import subprocess
   import sys

   VT_API_KEY = "TU_API_KEY_DE_VIRUSTOTAL"
   WAZUH_MANAGER = "localhost"

   def analyze_file(file_path):
       try:
           url = "https://www.virustotal.com/vtapi/v2/file/scan"
           files = {"file": open(file_path, "rb")}
           params = {"apikey": VT_API_KEY}
           response = requests.post(url, files=files, params=params)
           return response.json()
       except Exception as e:
           print(f"Error analyzing file: {e}")
           return {}

   def isolate_endpoint(agent_id):
       try:
           cmd = f"/var/ossec/bin/agent_control -l {agent_id} -i"
           subprocess.run(cmd, shell=True, check=True)
       except subprocess.CalledProcessError as e:
           print(f"Error isolating agent: {e}")

   def main():
       try:
           alert = json.loads(sys.stdin.read())
           agent_id = alert["agent"]["id"]
           file_path = alert["data"]["win"]["eventdata"]["destination"]
       except KeyError as e:
           print(f"Key error: {e}")
           return
       
       vt_result = analyze_file(file_path)
       
       if vt_result.get("positives", 0) > 5:
           isolate_endpoint(agent_id)
           print(f"Endpoint {agent_id} aislado por ransomware")
       else:
           print(f"Archivo {file_path} no es malicioso según VT")

   if __name__ == "__main__":
       main()
   ```

4. Haz el script ejecutable:
   ```bash
   sudo chmod +x /var/ossec/etc/scripts/ransomware-response.py
   ```

5. Copia el script a tu repositorio local:
   ```bash
   cp /var/ossec/etc/scripts/ransomware-response.py ~/lab-wazuh/configs/scripts/
   ```

#### 2.3 Configurar respuesta automática en Wazuh
1. Edita la configuración de Wazuh:
   ```bash
   sudo nano /var/ossec/etc/ossec.conf
   ```

2. Añade dentro de `<ossec_config>`:
   ```xml
   <command>
     <name>ransomware-response</name>
     <executable>ransomware-response.py</executable>
     <timeout_allowed>no</timeout_allowed>
   </command>

   <active-response>
     <command>ransomware-response</command>
     <location>local</location>
     <rules_id>100102,100103</rules_id>
   </active-response>
   ```

3. Reinicia Wazuh:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

#### 2.4 Probar la detección
1. En el Windows 10, crea un archivo con extensión sospechosa:
   ```cmd
   echo "test" > C:\temp\test.encrypted
   ```

2. Verifica las alertas en el dashboard de Wazuh.
	Explore - Discover - poner en el filtro: rule.id: 100102 OR rule.id: 100103


3.	terminal server wazuh-manager
   ```bash
   sudo tail -f /var/ossec/logs/alerts/alerts.log | grep --color=always -i "encrypted\|100102\|100103"
   ```






