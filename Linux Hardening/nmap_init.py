import nmap
import os
from datetime import datetime

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_output(directory, filename, content):
    try:
        with open(os.path.join(directory, filename), 'w') as f:
            f.write(content)
    except IOError as e:
        print(f"Error saving {filename}: {e}")

def scan_subnet(subnet):
    nm = nmap.PortScanner()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    main_dir = f"nmap_scan_{timestamp}"
    create_directory(main_dir)
    
    try:
        print(f"Discovering active hosts on {subnet}...")
        nm.scan(hosts=subnet, arguments='-sn')
        active_hosts = nm.all_hosts()
        
        save_output(main_dir, "active_hosts.txt", "\n".join(active_hosts))
        print(f"Found {len(active_hosts)} active hosts.")
    except nmap.PortScannerError as e:
        print(f"Error during host discovery: {e}")
        return
    
    for host in active_hosts:
        print(f"Scanning {host}...")
        host_dir = os.path.join(main_dir, f"host_{host}")
        create_directory(host_dir)
        
        try:
            # OS detection
            nm.scan(host, arguments='-O')
            os_output = nm[host].get('osmatch', [{}])[0].get('name', 'Unknown OS')
            save_output(host_dir, "os_detection.txt", os_output)
        except Exception as e:
            print(f"Error during OS detection for {host}: {e}")
        
        try:
            # Service and version detection
            nm.scan(host, arguments='-sV')
            service_output = str(nm[host].get('tcp', {}))
            save_output(host_dir, "service_version.txt", service_output)
        except Exception as e:
            print(f"Error during service detection for {host}: {e}")
        
        try:
            # Vulnerability scanning
            nm.scan(host, arguments='--script vuln')
            vuln_output = str(nm[host].get('tcp', {}))
            save_output(host_dir, "vulnerabilities.txt", vuln_output)
        except Exception as e:
            print(f"Error during vulnerability scanning for {host}: {e}")
        
        try:
            # Get hostname
            hostname = nm[host].hostname() if nm[host].hostname() else host
            os.rename(host_dir, os.path.join(main_dir, f"{hostname}_{host}"))
        except Exception as e:
            print(f"Error getting hostname for {host}: {e}")
    
    print("Scan completed. Results saved in the output directory.")

# Usage
subnet = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ")
scan_subnet(subnet)
