#!/usr/bin/env python3
import json
import requests
import subprocess
import sys

VT_API_KEY = "3e4c3ca07208976acab2e2cee63fbeba7bfd1ba6c53bf4a19a613436eeabe0a"b
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
