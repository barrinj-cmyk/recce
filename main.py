import nmap as nm
import os
from google import genai
vulnerabilities = []
outpuvulns = []
target_ip = input("Enter the target IP address: ")


def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True
while not validate_ip(target_ip):
    print("Invalid IP address. Please enter a valid IP address.")
    target_ip = input("Enter the target IP address: ")

#Scanning the target IP for open ports and services, banner grabbing, service identification, network mapping, and OS detection, network discovery, and enumeration using Nmap
scanner = nm.PortScanner()
print(f"Scanning {target_ip} for open ports and services...")
scanner.scan(target_ip, arguments='-sS -sV -sC -O --top-ports 1000 -T4')
print(f"Scan completed for {target_ip}. Extracting vulnerabilities...")
for host in scanner.all_hosts():
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        for port in ports:
            service = scanner[host][proto][port]['name']
            banner = scanner[host][proto][port]['product'] + " " + scanner[host][proto][port]['version']
            vulnerabilities.append({
                "host": host,
                "port": port,
                "service": service,
                "banner": banner
            })


#Vulnerability assessment using Google GenAI
print(f"Assessing vulnerabilities for {target_ip} using GenAI...")
genai_client = genai.Client()
for vuln in vulnerabilities:
    prompt = f"You are a cybersecurity expert. Identify vulnerabilities for the following service:\nService: {vuln['service']}\nBanner: {vuln['banner']}"
    response = genai_client.generate_content(prompt)
    outpuvulns.append({
        "host": vuln['host'],
        "port": vuln['port'],
        "service": vuln['service'],
        "vulnerabilities": response.text
    })

#Reporting
print(f"Vulnerability assessment completed for {target_ip}. Generating report...")
for vuln in outpuvulns:
    print(f"Host: {vuln['host']}")
    print(f"Port: {vuln['port']}")
    print(f"Service: {vuln['service']}")
    print(f"Vulnerabilities: {vuln['vulnerabilities']}\n")

print("Report generated successfully. Saving to vulnerability_report.txt...")
#Writing to file 
with open("vulnerability_report.txt", "w") as report_file:
    for vuln in outpuvulns:
        report_file.write(f"Host: {vuln['host']}\n")
        report_file.write(f"Port: {vuln['port']}\n")
        report_file.write(f"Service: {vuln['service']}\n")
        report_file.write(f"Vulnerabilities: {vuln['vulnerabilities']}\n\n")
print("Report saved successfully as vulnerability_report.txt.")


