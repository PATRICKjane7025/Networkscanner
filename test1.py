from flask import Flask, render_template, request, jsonify
import socket
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import os
import scapy.all as scapy
from typing import Dict, List

app = Flask(__name__)

# Load modules (ensure these are correct or replace them with the actual data structures)
from port import ports  # Contains list of common ports
from vv import version  # Version info for services
from vuln import vulners  # Vulnerabilities based on version
from ss import tags  # Service misconfigurations
from snipe import snipervulns  # Sn1per vulnerabilities

def get_ip_from_url(url: str) -> str:
    """Fetch IP from the URL"""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or parsed_url.path.split('/')[0]
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError("Invalid URL or hostname could not be resolved")

def ping_sweep(subnet: str) -> List[str]:
    """Perform a ping sweep on the given subnet"""
    live_hosts = []
    print(f"Starting Ping Sweep on {subnet}...")

    for ip in range(1, 255):
        ip_addr = f"{subnet}.{ip}"
        response = os.system(f"ping -c 1 -W 1 {ip_addr} > /dev/null 2>&1")

        if response == 0:
            live_hosts.append(ip_addr)
            print(f"Host {ip_addr} is alive")

    return live_hosts

def traceroute(target_ip: str) -> str:
    """Perform a traceroute to the given target IP"""
    print(f"Starting Traceroute to {target_ip}...")
    result = subprocess.run(["traceroute", target_ip], capture_output=True, text=True)
    print(result.stdout)
    return result.stdout

def check_open_ports(ip: str) -> List[int]:
    """Check for open ports on the given IP"""
    open_ports = []
    for port in ports:  # Scanning common ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def version_vulnerability_detection(ip: str, port: int) -> str:
    """Detect version-based vulnerabilities"""
    if port in version:
        service = version[port]
        vulnerabilities = ', '.join(map(str, vulners[service])) if service in vulners else "No known vulnerabilities"
        return f"Port {port} ({service}): Potential Vulnerabilities: {vulnerabilities}"
    else:
        return f"Port {port}: Not in top 100 scanned ports."

def service_misconfiguration_detection(ip: str, port: int) -> str:
    """Detect service misconfigurations"""
    if port in version:
        service = version[port]
        misconfigurations = ', '.join(map(str, tags[service])) if service in tags else "No known misconfigurations"
        return f"Port {port} ({service}): Potential Misconfigurations: {misconfigurations}"
    else:
        return f"Port {port}: Not in top 100 scanned ports."

def sniper_vulnerability_detection(ip: str, port: int) -> str:
    """Detect Sn1per vulnerabilities"""
    if port in version:
        service = version[port]
        vulnerabilities = ', '.join(map(str, snipervulns[service])) if service in snipervulns else "No known Sn1per vulnerabilities"
        return f"Port {port} ({service}): Sn1per Vulnerabilities Detected: {vulnerabilities}"
    else:
        return f"Port {port}: Not in top 100 scanned ports."



def perform_scan(ip: str) -> Dict[str, List[str]]:
    """Perform a scan on the given IP"""
    result = {}
    open_ports = check_open_ports(ip)
    result['Open Ports'] = open_ports

    vulnerabilities = []
    misconfigs = []
    sniper_vulns = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(version_vulnerability_detection, ip, port): port for port in open_ports
        }
        for future in futures:
            vulnerabilities.append(future.result())

        futures_misconfigs = {
            executor.submit(service_misconfiguration_detection, ip, port): port for port in open_ports
        }
        for future in futures_misconfigs:
            misconfigs.append(future.result())

        futures_sniper = {
            executor.submit(sniper_vulnerability_detection, ip, port): port for port in open_ports
        }
        for future in futures_sniper:
            sniper_vulns.append(future.result())

    result['Version-Based Vulnerabilities'] = vulnerabilities
    result['Service Misconfigurations'] = misconfigs
    result['Sn1per Vulnerabilities'] = sniper_vulns

    return result

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if 'authorized' not in request.form:
            return "Please confirm you are authorized to scan this target.", 400
        
        target = request.form["target"]
        
        try:
            if target.startswith("http://") or target.startswith("https://"):
                ip = get_ip_from_url(target)
            else:
                ip = socket.gethostbyname(target)  # Resolve the IP if it's a hostname
            
            scan_results = perform_scan(ip)
            return render_template("index.html", scan_results=scan_results, target=target)
        
        except ValueError as e:
            return f"Error: {str(e)}", 400  # Handle URL or hostname errors
        except Exception as e:
            return f"Error: {str(e)}", 500
    
    return render_template("index.html", scan_results=None)

if __name__ == "__main__":
    app.run(debug=True)