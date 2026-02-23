import nmap
import sys
import shutil
from google import genai

vulnerabilities = []
outpuvulns = []

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
    sys.exit(1)

portscanner = nmap.PortScanner()
vulnscanner = nmap.PortScanner()

openPorts = []

print(f"Scanning {targIP} for open ports...")

try:
    portscanner.scan(targIP, arguments='-sS --top-ports 1000 -T4')

    for host in portscanner.all_hosts():
        for proto in portscanner[host].all_protocols():
            for port in portscanner[host][proto].keys():
                if portscanner[host][proto][port]['state'] == 'open':
                    openPorts.append(str(port))

    if not openPorts:
        print("No open ports found.")
        sys.exit(0)

    port = ",".join(openPorts)

    print(f"Open ports found: {port}")
    print("Starting targeted vulnerability scan...")

    vulnscanner.scan(
        targIP,
        arguments=f'-sV --script=vuln --script-timeout 15s -p {port} -T4'
    )

    for host in vulnscanner.all_hosts():
        for proto in vulnscanner[host].all_protocols():
            for port in vulnscanner[host][proto].keys():
                data = vulnscanner[host][proto][port]

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
    sys.exit(1)

print("Scan complete.")
print(f"Assessing vulnerabilities for {targIP} using GenAI...")

try:
    genai_client = genai.Client()

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
    with open("vulnerability_report.txt", "w") as report_file:
        for vuln in outpuvulns:
            report_file.write(f"Host: {vuln['host']}\n")
            report_file.write(f"Vulnerabilities:\n{vuln['analysis']}\n\n")

    print("Report saved successfully as vulnerability_report.txt.")

except Exception as e:
    print(f"Failed to save report: {e}")