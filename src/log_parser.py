import re

def parse_apache_log(filepath):
    entries = []
    pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) HTTP/\d\.\d" (\d+) (\S+)'
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            match = re.match(pattern, line)
            if match:
                entries.append({
                    'source_ip': match.group(1),
                    'timestamp': match.group(2),
                    'method': match.group(3),
                    'uri': match.group(4),
                    'status_code': int(match.group(5)),
                    'size': match.group(6)
                })
    return entries
