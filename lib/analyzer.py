"""Forensic log analyzer - shared logic for Vercel serverless."""
import re
from urllib.parse import unquote


def parse_log_line(line):
    regex = r'^(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(\w+)\s+(.+?)\s+HTTP/[\d.]+"\s+(\d+)\s+(\d+|-)'
    match = re.search(regex, line)
    if match:
        size_val = match.group(6)
        size = int(size_val) if size_val.isdigit() else 0
        return {
            "ip": match.group(1),
            "timestamp": match.group(2),
            "method": match.group(3),
            "path": match.group(4),
            "status": int(match.group(5)),
            "size": size
        }
    return None


def detect_anomalies(logs):
    anomalies = []
    ip_stats = {}
    sensitive_patterns = [
        r'\.\./', r'etc/passwd', r'proc/self', r'eval\(', r'<script>',
        r'UNION\s+SELECT', r'ORDER\s+BY', r'information_schema',
        r'base64_', r'system\(', r'cmd\.exe'
    ]
    sensitive_paths = ['/admin', '/config', '/.env', '/.git', '/wp-admin', '/phpmyadmin', '/setup', '/.htaccess', '/config.php', '/install.php', '/phpinfo.php', '/server-status']

    for log in logs:
        ip = log['ip']
        path = unquote(log['path']).lower()
        if ip not in ip_stats:
            ip_stats[ip] = {'count': 0, '401s': 0, 'bytes': 0, 'last_ts': log['timestamp'], 'paths': set()}
        ip_stats[ip]['count'] += 1
        ip_stats[ip]['bytes'] += log['size']
        ip_stats[ip]['paths'].add(path)

        if log['status'] == 401:
            ip_stats[ip]['401s'] += 1
            if ip_stats[ip]['401s'] == 5:
                anomalies.append({"type": "Brute Force Attempt", "severity": "High", "description": f"Persistent authentication failures (5+) from IP {ip}", "timestamp": log['timestamp']})
        if any(s_path in path for s_path in sensitive_paths):
            anomalies.append({"type": "Unauthorized Access Attempt", "severity": "Critical", "description": f"Access to sensitive path {log['path']} from {ip}", "timestamp": log['timestamp']})
        if any(re.search(p, path, re.I) for p in sensitive_patterns):
            anomalies.append({"type": "Web Exploit Attempt", "severity": "Critical", "description": f"Suspicious payload/pattern detected in request path from {ip}", "timestamp": log['timestamp']})

    for ip, stats in ip_stats.items():
        if stats['bytes'] > 5000000:
            anomalies.append({"type": "Potential Data Exfiltration", "severity": "High", "description": f"Large data transfer ({stats['bytes']} bytes) to IP {ip}", "timestamp": stats['last_ts']})
        if stats['count'] > 100:
            anomalies.append({"type": "Anomalous Traffic Peak", "severity": "Medium", "description": f"High volume of requests ({stats['count']}) from single source {ip}", "timestamp": stats['last_ts']})
        if len(stats['paths']) > 20:
            anomalies.append({"type": "Directory Scanning", "severity": "Medium", "description": f"IP {ip} accessed {len(stats['paths'])} unique paths (potential fuzzing)", "timestamp": stats['last_ts']})

    return anomalies
