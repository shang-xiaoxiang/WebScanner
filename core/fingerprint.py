import re
import json
import os
from bs4 import BeautifulSoup

class FingerprintDB:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'fingerprints', 'fingerprints.json')
        self.config_path = config_path
        self._load_config()
    
    def _load_config(self):
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.server_fingerprints = config.get('servers', {})
            self.cms_fingerprints = config.get('cms', {})
            self.programming_languages = config.get('programming_languages', {})
            self.middleware = config.get('middleware', {})
            self.waf_fingerprints = config.get('waf', {})
            self.sensitive_paths = config.get('sensitive_paths', [])
            
            # 转换端口为整数
            self.common_ports = {}
            for port_str, service in config.get('common_ports', {}).items():
                try:
                    self.common_ports[int(port_str)] = service
                except ValueError:
                    pass
        except Exception as e:
            # 加载失败时使用默认配置
            self._load_default_config()
    
    def _load_default_config(self):
        # 默认配置作为后备
        self.server_fingerprints = {
            'Apache': {
                'headers': ['Server: Apache', 'Server: Apache/'],
                'keywords': ['Apache'],
                'meta_tags': [],
                'paths': []
            },
            'Nginx': {
                'headers': ['Server: nginx'],
                'keywords': ['nginx'],
                'meta_tags': [],
                'paths': []
            }
        }
        self.cms_fingerprints = {}
        self.programming_languages = {}
        self.middleware = {}
        self.waf_fingerprints = {}
        self.sensitive_paths = []
        self.common_ports = {
            80: 'HTTP',
            443: 'HTTPS'
        }
    
    def identify_server(self, headers, content, status_code=None, cookies=None, tls_info=None):
        detected_servers = []
        content_lower = content.lower() if content else ''
        
        for server_name, fingerprint in self.server_fingerprints.items():
            if self._match_fingerprint(headers, content_lower, fingerprint, status_code, cookies, tls_info):
                detected_servers.append(server_name)
        
        return detected_servers
    
    def identify_cms(self, headers, content, url, status_code=None, cookies=None, tls_info=None):
        detected_cms = []
        content_lower = content.lower() if content else ''
        url_lower = url.lower() if url else ''
        
        for cms_name, fingerprint in self.cms_fingerprints.items():
            if self._match_fingerprint(headers, content_lower, fingerprint, status_code, cookies, tls_info):
                detected_cms.append(cms_name)
            elif self._match_path(url_lower, fingerprint.get('paths', [])):
                detected_cms.append(cms_name)
        
        return detected_cms
    
    def _match_fingerprint(self, headers, content, fingerprint, status_code=None, cookies=None, tls_info=None):
        headers_str = str(headers).lower() if headers else ''
        cookies_str = str(cookies).lower() if cookies else ''
        
        # 检查响应头
        for header in fingerprint.get('headers', []):
            if header.lower() in headers_str:
                return True
        
        # 检查内容关键词
        for keyword in fingerprint.get('keywords', []):
            if keyword.lower() in content:
                return True
        
        # 检查元标签
        if content:
            try:
                soup = BeautifulSoup(content, 'html.parser')
                for meta_tag in fingerprint.get('meta_tags', []):
                    if isinstance(meta_tag, list) and len(meta_tag) == 2:
                        name, content_value = meta_tag
                        meta = soup.find('meta', {'name': name})
                        if meta and content_value.lower() in meta.get('content', '').lower():
                            return True
            except Exception:
                pass
        
        # 检查状态码
        if status_code and status_code in fingerprint.get('status_codes', []):
            return True
        
        # 检查Cookie
        for cookie in fingerprint.get('cookies', []):
            if cookie.lower() in cookies_str:
                return True
        
        # 检查TLS证书信息
        if tls_info:
            for tls_key, tls_value in fingerprint.get('tls', {}).items():
                if tls_key in tls_info and tls_value.lower() in str(tls_info[tls_key]).lower():
                    return True
        
        return False
    
    def _match_path(self, url, paths):
        for path in paths:
            if path.lower() in url:
                return True
        return False
    
    def get_sensitive_paths(self):
        return self.sensitive_paths
    
    def get_common_ports(self):
        return self.common_ports
    
    def identify_waf(self, headers, content, status_code):
        detected_waf = []
        content_lower = content.lower() if content else ''
        headers_str = str(headers).lower() if headers else ''
        
        for waf_name, fingerprint in self.waf_fingerprints.items():
            # 检查响应头
            for header in fingerprint.get('headers', []):
                if header.lower() in headers_str:
                    detected_waf.append(waf_name)
                    break
            
            # 检查内容
            for keyword in fingerprint.get('keywords', []):
                if keyword.lower() in content_lower:
                    detected_waf.append(waf_name)
                    break
            
            # 检查状态码
            if status_code in fingerprint.get('status_codes', []):
                detected_waf.append(waf_name)
                break
        
        # 去重
        return list(set(detected_waf))
    
    def identify_programming_language(self, headers, content, status_code=None, cookies=None, tls_info=None):
        detected_languages = []
        content_lower = content.lower() if content else ''
        
        for language, fingerprint in self.programming_languages.items():
            if self._match_fingerprint(headers, content_lower, fingerprint, status_code, cookies, tls_info):
                detected_languages.append(language)
        
        return detected_languages
    
    def identify_middleware(self, headers, content, open_ports, status_code=None, cookies=None, tls_info=None):
        detected_middleware = []
        content_lower = content.lower() if content else ''
        
        for middleware, fingerprint in self.middleware.items():
            # 检查端口
            ports = fingerprint.get('ports', [])
            for port in ports:
                if port in open_ports:
                    detected_middleware.append(middleware)
                    break
            
            # 检查指纹
            if self._match_fingerprint(headers, content_lower, fingerprint, status_code, cookies, tls_info):
                detected_middleware.append(middleware)
        
        # 去重
        return list(set(detected_middleware))