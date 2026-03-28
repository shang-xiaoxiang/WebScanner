import re
import socket
from urllib.parse import urlparse

def is_ip_address(ip):
    """检查是否为有效的IP地址"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_domain(domain):
    """检查是否为有效的域名"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_url(url):
    """检查是否为有效的URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_valid_port(port):
    """检查是否为有效的端口号"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def normalize_url(url):
    """标准化URL"""
    if is_ip_address(url):
        return f'http://{url}'
    
    if not url.startswith(('http://', 'https://')):
        return f'http://{url}'
    
    return url
