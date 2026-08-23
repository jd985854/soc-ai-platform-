SUSPICIOUS_PATTERNS = {
    'SQLi': ["'", "OR 1=1", "UNION SELECT", "--"],
    'Path_Traversal': ["../", "..\\", "/etc/passwd"],
    'Command_Injection': [";", "&&", "|", "`"],
    'XSS': ["<script>", "javascript:", "onload="]
}

def correlate(vuln, log_entries):
    suspicious_found = []
    pattern_hits = []
    
    for log in log_entries:
        uri = log['uri']
        for attack_type, patterns in SUSPICIOUS_PATTERNS.items():
            for p in patterns:
                if p in uri:
                    pattern_hits.append(attack_type)
                    suspicious_found.append(log)
                    break
    
    external_ips = set()
    for log in log_entries:
        ip = log['source_ip']
        if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.')):
            external_ips.add(ip)
    
    return {
        'total_logs_analyzed': len(log_entries),
        'suspicious_entries': len(suspicious_found),
        'detected_patterns': list(set(pattern_hits)),
        'external_sources_count': len(external_ips),
        'external_ips': list(external_ips),
        'correlation_score': min(10, 2 + (len(suspicious_found) * 0.5) + (len(external_ips) * 0.5))
    }
