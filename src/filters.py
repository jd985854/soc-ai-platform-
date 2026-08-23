PROD_IPS = ['192.168.1.10', '10.0.0.5']
TEST_IPS = ['192.168.1.20', '10.0.0.6']

def apply_rules(vulns):
    filtered = []
    for v in vulns:
        if v['cvss_score'] < 4.0:
            continue
        if 'SSL' in v['plugin_name'] or 'TLS' in v['plugin_name']:
            continue
        if 'Nessus' in v['plugin_name'] and v['risk'] == 'none':
            continue
        filtered.append(v)
    return filtered

def apply_context(vulns):
    filtered = []
    for v in vulns:
        host = v['host']
        if host in TEST_IPS and v['cvss_score'] < 9.0:
            continue
        if host in PROD_IPS:
            v['environment'] = 'production'
            filtered.append(v)
        else:
            v['environment'] = 'unknown'
            filtered.append(v)
    return filtered
