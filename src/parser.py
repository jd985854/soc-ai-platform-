import xmltodict

def parse_nessus(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = xmltodict.parse(f.read())
    
    vulns = []
    try:
        report_hosts = data.get('NessusClientData_v2', {}).get('Report', {}).get('ReportHost', [])
        if not isinstance(report_hosts, list):
            report_hosts = [report_hosts]
        
        for host in report_hosts:
            host_ip = host.get('@name', 'Unknown')
            items = host.get('ReportItem', [])
            if not isinstance(items, list):
                items = [items]
            
            for item in items:
                vuln = {
                    'plugin_id': item.get('@pluginID', 'N/A'),
                    'cve': item.get('@cve', 'N/A'),
                    'cvss_score': float(item.get('@cvss_base_score', 0)),
                    'risk': item.get('@risk_factor', 'none').lower(),
                    'host': host_ip,
                    'port': item.get('@port', 'N/A'),
                    'description': item.get('description', 'No description'),
                    'solution': item.get('solution', 'No solution'),
                    'plugin_name': item.get('@pluginName', 'Unknown')
                }
                if vuln['cve'] != 'N/A' or vuln['cvss_score'] >= 5.0:
                    vulns.append(vuln)
    except Exception as e:
        print(f"Parser Error: {e}")
    return vulns
