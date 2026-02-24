import nmap
import sys
import shutil
from google import genai
import time

vulnerabilities = []
outpuvulns = []

genai_api_key = input("Enter your GenAI API key: ")
targIP = input("Enter the target IP address: ")

def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

while not validate_ip(targIP):
    print("Invalid IP address. Please enter a valid IP address.")
    targIP = input("Enter the target IP address: ")

if not shutil.which("nmap"):
    print("Error: Nmap is not installed or not in PATH.")
    time.sleep(4)
    sys.exit(1)

scanner = nmap.PortScanner()

print(f"Scanning {targIP} for open ports and vulnerabilities...")

try:
    scanner.scan(targIP, arguments='-sV -O -T5 --version-light --osscan-limit --top-ports 1000')

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                data = scanner[host][proto][port]

                service = data.get('name', '')
                product = data.get('product', '')
                version = data.get('version', '')

                banner = f"{product} {version}".strip()

                vulnerabilities.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "scripts": data.get('script', {})
                })

except Exception as e:
    print(f"Scan failed: {e}")
    time.sleep(4)
    sys.exit(1)

print("Scan complete.")
print(f"Assessing vulnerabilities for {targIP} using GenAI...")
print(f"Assessing vulnerabilities for {targIP} using GenAI...")

try:
    genai_client = genai.Client(api_key=genai_api_key)

    combined_prompt = ""
    for vuln in vulnerabilities:
        combined_prompt += (
            f"Host: {vuln['host']}\n"
            f"Port: {vuln['port']}\n"
            f"Service: {vuln['service']}\n"
            f"Banner: {vuln['banner']}\n"
            f"Nmap Script Output: {vuln['scripts']}\n\n"
        )

    prompt = (
        "You are a cybersecurity expert. Identify known vulnerabilities, "
        "possible CVEs, risk level, and remediation steps for the following services:\n\n"
        + combined_prompt
    )

    response = genai_client.models.generate_content(
        model="gemini-1.5-flash",
        contents=prompt
    )

    ai_output = response.text

    outpuvulns.append({
        "host": targIP,
        "analysis": ai_output
    })

except Exception as e:
    print(f"GenAI analysis failed: {e}")
    outpuvulns.append({
        "host": targIP,
        "analysis": "AI analysis unavailable."
    })

print(f"Vulnerability assessment completed for {targIP}. Generating report...")

for vuln in outpuvulns:
    print(f"Host: {vuln['host']}")
    print(f"Vulnerabilities:\n{vuln['analysis']}\n")

print("Report generated successfully. Saving to vulnerability_report.txt...")

try:
    with open("vulnerability_report.txt", "w") as report:
        for vuln in outpuvulns:
            report.write(f"Host: {vuln['host']}\n")
            report.write(f"Vulnerabilities:\n{vuln['analysis']}\n\n")

    print("Report saved successfully as vulnerability_report.txt.")

except Exception as e:
    print(f"Failed to save report: {e}")