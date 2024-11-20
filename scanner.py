import socket
import termcolor
import requests
from Banner import display_banner


class PortScanner:
    def __init__(self, targets, ports):
        self.targets = targets
        self.ports = ports

    def scan(self):
        for target in self.targets:
            print(termcolor.colored(f"\n[*] Scanning Target: {target}", 'light_blue'))
            domains = self.get_domains(target)
            print(
                termcolor.colored(f"[*] Associated Domains: {', '.join(domains) if domains else 'None Found'}", 'cyan'))
            info = self.get_additional_info(target)
            print(termcolor.colored(f"[*] Additional Info: {info}", 'cyan'))

            for port in range(1, self.ports + 1):
                self.scan_port(target, port)

    def scan_port(self, ip_address, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))  # Returns 0 for open ports
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown Service"
                banner = self.grab_banner(sock)
                print(termcolor.colored(f"[+] Open Port {port} ({service})", 'green'))
                if banner:
                    print(termcolor.colored(f"    Banner: {banner.strip()}", 'yellow'))
            else:
                print(termcolor.colored(f"[-] Closed/Filtered Port {port}", 'red'))
            sock.close()
        except Exception as e:
            print(termcolor.colored(f"[!] Error scanning port {port}: {e}", 'red'))

    def grab_banner(self, sock):
        try:
            sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
            return sock.recv(1024).decode('utf-8')
        except:
            return None

    def get_domains(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[1]  # Reverse DNS lookup
        except socket.herror:
            return []

    def get_additional_info(self, ip_address):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            if response.status_code == 200:
                data = response.json()
                return {
                    "IP": data.get("ip"),
                    "Organization": data.get("org"),
                    "ISP": data.get("hostname"),
                    "City": data.get("city"),
                    "Region": data.get("region"),
                    "Country": data.get("country"),
                }
            else:
                return "No information available"
        except Exception as e:
            return f"Error fetching additional info: {e}"


if __name__ == "__main__":
    display_banner()
    targets_input = input("[*] Enter Targets to Scan (separate by ,): ").strip()
    ports = int(input("[*] Enter How Many Ports to Scan: ").strip())

    if ',' in targets_input:
        targets = [ip.strip() for ip in targets_input.split(',')]
    else:
        targets = [targets_input]

    scanner = PortScanner(targets, ports)
    scanner.scan()
