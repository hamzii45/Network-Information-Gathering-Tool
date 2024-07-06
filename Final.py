import nmap
import dns.resolver

def domain_to_ip(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.to_text() for ip in result]
    except Exception as e:
        return f"Error resolving domain: {e}"

def mx_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'MX')
        return [record.exchange.to_text() for record in result]
    except Exception as e:
        return f"Error retrieving MX records: {e}"

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-T4')
    
    for host in nm.all_hosts():
        print(f"Scanning {host} for open ports...")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            if input("Do you want to scan specific ports? (y/n): ").lower() == 'y':
                specific_ports = input("Enter specific ports (comma-separated): ")
                specific_args = f"-p {specific_ports} -T4"
                nm.scan(hosts=target, arguments=specific_args)
                ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                print(f"Port {port}/{proto} is {state}")

def detect_os(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-O')  # OS detection only
    
    for host in nm.all_hosts():
        if 'osmatch' in nm[host]:
            os_info = nm[host]['osmatch'][0]['name']
            print(f"Operating System: {os_info}")
        else:
            print("OS detection not available for this host.")

def detect_services(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV')  # Service version detection
    
    for host in nm.all_hosts():
        print(f"Detecting services on {host}...")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                print(f"Service on port {port}/{proto}: {service} {version}")

def detect_databases(target):
    nm = nmap.PortScanner()
    common_db_ports = "3306,5432,1433,1521,27017"  # MySQL, PostgreSQL, MSSQL, Oracle, MongoDB
    nm.scan(hosts=target, arguments=f"-p {common_db_ports}")
    
    for host in nm.all_hosts():
        print(f"Detecting databases on {host}...")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if port in [3306, 5432, 1433, 1521, 27017]:
                    state = nm[host][proto][port]['state']
                    print(f"Database on port {port}/{proto} is {state}")

def network_mapping(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sP')  # Ping scan for network mapping
    
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                print(f"Port {port}/{proto} is {state}")

if __name__ == "__main__":
    domain = input("Enter a domain to resolve: ")
    ips = domain_to_ip(domain)
    print(f"IP addresses for {domain}: {ips}")

    mx = mx_records(domain)
    print(f"MX records for {domain}: {mx}")

    target = input("Enter a domain or IP address to scan: ")
    scan_ports(target)
    
    if input("Do you want to see OS detection results? (y/n): ").lower() == 'y':
        detect_os(target)
    
    if input("Do you want to detect services? (y/n): ").lower() == 'y':
        detect_services(target)
    
    if input("Do you want to detect databases? (y/n): ").lower() == 'y':
        detect_databases(target)
    
    if input("Do you want to map the network? (y/n): ").lower() == 'y':
        network_mapping(target)
