import socket
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from core.fingerprint import FingerprintDB
import time

class WebScanner:
    def __init__(self):
        self.fingerprint_db = FingerprintDB()
        self.timeout = 5
        self.max_threads = 50
    
    def scan(self, target):
        result = {
            'target': target,
            'ip': self._resolve_ip(target),
            'open_ports': [],
            'server_info': [],
            'cms_info': [],
            'sensitive_paths': [],
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        url = self._normalize_url(target)
        if url:
            result['url'] = url
            
            http_result = self._scan_http(url)
            result.update(http_result)
        
        ports = self._scan_ports(result['ip'])
        result['open_ports'] = ports
        
        return result
    
    def _resolve_ip(self, target):
        try:
            if self._is_ip(target):
                return target
            return socket.gethostbyname(target)
        except Exception as e:
            return None
    
    def _is_ip(self, target):
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _normalize_url(self, target):
        if self._is_ip(target):
            return f'http://{target}'
        
        if not target.startswith(('http://', 'https://')):
            return f'http://{target}'
        
        return target
    
    def _scan_ports(self, ip):
        if not ip:
            return []
        
        open_ports = []
        common_ports = self.fingerprint_db.get_common_ports()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, ip, port): port for port in common_ports.keys()}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        service = common_ports[port]
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'status': 'open'
                        })
                except Exception as e:
                    pass
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def _check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _scan_http(self, url):
        result = {
            'server_info': [],
            'cms_info': [],
            'waf_info': [],
            'sensitive_paths': []
        }
        
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = dict(response.headers)
            content = response.text
            status_code = response.status_code
            
            result['status_code'] = status_code
            result['content_length'] = len(content)
            
            servers = self.fingerprint_db.identify_server(headers, content)
            result['server_info'] = servers
            
            cms_list = self.fingerprint_db.identify_cms(headers, content, url)
            result['cms_info'] = cms_list
            
            waf_list = self.fingerprint_db.identify_waf(headers, content, status_code)
            result['waf_info'] = waf_list
            
            sensitive_paths = self._scan_sensitive_paths(url)
            result['sensitive_paths'] = sensitive_paths
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result
    
    def _scan_sensitive_paths(self, base_url):
        sensitive_paths = self.fingerprint_db.get_sensitive_paths()
        found_paths = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_path, base_url, path): path for path in sensitive_paths}
            
            for future in as_completed(futures):
                path = futures[future]
                try:
                    status = future.result()
                    if status:
                        found_paths.append({
                            'path': path,
                            'status': status
                        })
                except Exception:
                    pass
        
        return found_paths
    
    def _check_path(self, base_url, path):
        try:
            url = base_url.rstrip('/') + path
            response = requests.get(url, timeout=3, allow_redirects=False)
            
            if response.status_code == 200:
                return 'accessible'
            elif response.status_code == 403:
                return 'forbidden'
            elif response.status_code == 301 or response.status_code == 302:
                return 'redirect'
            
            return None
        except requests.exceptions.RequestException:
            return None
    
    def quick_scan(self, target):
        result = {
            'target': target,
            'ip': self._resolve_ip(target),
            'server_info': [],
            'cms_info': [],
            'waf_info': [],
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        url = self._normalize_url(target)
        if url:
            result['url'] = url
            
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                headers = dict(response.headers)
                content = response.text
                status_code = response.status_code
                
                result['status_code'] = status_code
                
                servers = self.fingerprint_db.identify_server(headers, content)
                result['server_info'] = servers
                
                cms_list = self.fingerprint_db.identify_cms(headers, content, url)
                result['cms_info'] = cms_list
                
                waf_list = self.fingerprint_db.identify_waf(headers, content, status_code)
                result['waf_info'] = waf_list
                
            except requests.exceptions.RequestException as e:
                result['error'] = str(e)
        
        return result