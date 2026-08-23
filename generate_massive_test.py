import random
import time

# Configuration
TOTAL_VULNS = 4500
PROD_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
TEST_IPS = [f"192.168.1.{i}" for i in range(30, 50)]

# CVE Pool (mix of critical, high, medium, low)
CVE_POOL = [
    ("CVE-2023-1234", "SQL Injection", 9.8, "Critical"),
    ("CVE-2021-44228", "Log4Shell RCE", 10.0, "Critical"),
    ("CVE-2023-4567", "XSS Vulnerability", 7.5, "High"),
    ("CVE-2017-5638", "Struts2 RCE", 9.8, "Critical"),
    ("CVE-2020-0796", "SMBGhost", 10.0, "Critical"),
    ("CVE-2023-5678", "SSH Brute Force", 7.5, "High"),
    ("CVE-2023-7890", "Path Traversal", 7.5, "High"),
    ("CVE-2023-9012", "Tomcat Manager", 9.0, "Critical"),
    ("CVE-2023-6789", "TLS Weak Ciphers", 8.0, "High"),
    ("SSL Certificate Expiry", "SSL Cert", 4.0, "None"),
    ("NTP Info Disclosure", "NTP", 2.5, "None"),
    ("Nessus Scanner Noise", "Nessus", 0.0, "None"),
]

def generate_nessus():
    xml = '<NessusClientData_v2>\n  <Report name="Massive 4500 Test">\n'
    
    for i in range(TOTAL_VULNS):
        # Randomly select a vulnerability
        cve, name, cvss, risk = random.choice(CVE_POOL)
        
        # Determine IP (70% Prod, 20% Test, 10% Unknown)
        rand_ip = random.random()
        if rand_ip < 0.7:
            host = random.choice(PROD_IPS)
        elif rand_ip < 0.9:
            host = random.choice(TEST_IPS)
        else:
            host = f"10.0.0.{random.randint(1, 100)}"  # Unknown
        
        # Random port
        port = random.choice(["80", "443", "22", "445", "3306", "8080", "8443"])
        
        # Add unique entry
        xml += f'    <ReportHost name="{host}">\n'
        xml += f'      <ReportItem pluginID="{i+1000}" cve="{cve}" cvss_base_score="{cvss}" risk_factor="{risk}" port="{port}" pluginName="{name}">\n'
        xml += f'        <description>Automated test finding #{i+1}: {name}</description>\n'
        xml += f'        <solution>Apply appropriate patch or mitigation.</solution>\n'
        xml += f'      </ReportItem>\n'
        xml += f'    </ReportHost>\n'
    
    xml += '  </Report>\n</NessusClientData_v2>'
    
    with open('sample_data/massive_4500.nessus', 'w') as f:
        f.write(xml)
    print(f"[+] Generated {TOTAL_VULNS} vulnerabilities in 'sample_data/massive_4500.nessus'")

def generate_logs():
    log_lines = []
    attack_patterns = [
        ("' OR 1=1", "SQLi"),
        ("UNION SELECT", "SQLi"),
        ("<script>", "XSS"),
        ("../", "Path Traversal"),
        ("${jndi:", "Log4Shell"),
        ("; whoami", "CMD Injection"),
    ]
    
    # Generate 5,000 log lines (mix of benign and malicious)
    for _ in range(5000):
        # 30% chance it's an attack
        if random.random() < 0.3:
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            pattern, attack_type = random.choice(attack_patterns)
            uri = f"/api/data?q={pattern}&user=admin"
            status = random.choice([200, 404, 500])
            log_lines.append(f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {uri} HTTP/1.1" {status} 512\n')
        else:
            # Normal traffic
            ip = random.choice(["192.168.1.5", "10.0.0.2", "192.168.1.10"])
            log_lines.append(f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.html HTTP/1.1" 200 1024\n')
    
    with open('sample_data/massive_4500.log', 'w') as f:
        f.writelines(log_lines)
    print(f"[+] Generated {len(log_lines)} log entries in 'sample_data/massive_4500.log'")

if __name__ == '__main__':
    import os
    os.makedirs('sample_data', exist_ok=True)
    generate_nessus()
    generate_logs()
