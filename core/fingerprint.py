import re

class FingerprintDB:
    def __init__(self):
        self.server_fingerprints = {
            'Apache': {
                'headers': ['Server: Apache', 'Server: Apache/'],
                'keywords': ['Apache'],
                'meta_tags': []
            },
            'Nginx': {
                'headers': ['Server: nginx'],
                'keywords': ['nginx'],
                'meta_tags': []
            },
            'IIS': {
                'headers': ['Server: Microsoft-IIS', 'Server: IIS'],
                'keywords': ['IIS'],
                'meta_tags': []
            },
            'Tomcat': {
                'headers': ['Server: Apache-Coyote', 'Server: Tomcat'],
                'keywords': ['Tomcat', 'Apache-Coyote'],
                'meta_tags': []
            },
            'Lighttpd': {
                'headers': ['Server: lighttpd'],
                'keywords': ['lighttpd'],
                'meta_tags': []
            },
            'BWS': {
                'headers': ['Server: BWS/'],
                'keywords': ['BWS'],
                'meta_tags': []
            },
            'Tengine': {
                'headers': ['Server: Tengine'],
                'keywords': ['Tengine'],
                'meta_tags': []
            },
            'AliyunSLB': {
                'headers': ['Server: AliyunSLB'],
                'keywords': ['AliyunSLB'],
                'meta_tags': []
            },
            'Tencent': {
                'headers': ['Server: Tengine', 'Server: QWS'],
                'keywords': ['Tengine', 'QWS'],
                'meta_tags': []
            },
            'Jingdong': {
                'headers': ['Server: JDWS'],
                'keywords': ['JDWS'],
                'meta_tags': []
            },
            'Huawei': {
                'headers': ['Server: HuaweiCloud'],
                'keywords': ['HuaweiCloud'],
                'meta_tags': []
            },
            'Cloudflare': {
                'headers': ['Server: cloudflare', 'Server: Cloudflare'],
                'keywords': ['cloudflare', 'Cloudflare'],
                'meta_tags': []
            },
            'Akamai': {
                'headers': ['Server: AkamaiGHost'],
                'keywords': ['AkamaiGHost', 'Akamai'],
                'meta_tags': []
            },
            'Fastly': {
                'headers': ['Server: Fastly'],
                'keywords': ['Fastly'],
                'meta_tags': []
            }
        }
        
        self.cms_fingerprints = {
            'WordPress': {
                'headers': ['X-Powered-By: WordPress'],
                'keywords': ['wp-content', 'wp-includes', 'wp-admin'],
                'meta_tags': ['generator', 'WordPress'],
                'paths': ['/wp-login.php', '/wp-admin/', '/wp-content/']
            },
            'Discuz': {
                'headers': ['X-Powered-By: Discuz'],
                'keywords': ['discuz', 'uc_server', 'uc_client'],
                'meta_tags': ['generator', 'Discuz'],
                'paths': ['/uc_server/', '/forum.php', '/data/config/']
            },
            'Dedecms': {
                'headers': ['X-Powered-By: Dedecms'],
                'keywords': ['dedecms', 'data/common.inc.php'],
                'meta_tags': ['generator', 'DedeCMS'],
                'paths': ['/dede/', '/plus/', '/data/']
            },
            'Drupal': {
                'headers': ['X-Powered-By: Drupal'],
                'keywords': ['drupal', 'sites/default'],
                'meta_tags': ['generator', 'Drupal'],
                'paths': ['/user/login', '/sites/default/']
            },
            'Joomla': {
                'headers': ['X-Powered-By: Joomla'],
                'keywords': ['joomla', 'components/com_'],
                'meta_tags': ['generator', 'Joomla'],
                'paths': ['/administrator/', '/components/']
            },
            'ThinkPHP': {
                'headers': ['X-Powered-By: ThinkPHP'],
                'keywords': ['thinkphp', 'think_'],
                'meta_tags': [],
                'paths': ['/thinkphp/', '/Public/']
            },
            'Struts2': {
                'headers': [],
                'keywords': ['struts2', 'struts.action.extension'],
                'meta_tags': [],
                'paths': ['/struts/', '/WEB-INF/']
            },
            'Spring Boot': {
                'headers': ['X-Application-Context'],
                'keywords': ['spring', 'boot'],
                'meta_tags': [],
                'paths': ['/actuator/', '/error']
            }
        }
        
        self.sensitive_paths = [
            '/admin/',
            '/administrator/',
            '/admin.php',
            '/login.php',
            '/config.php',
            '/backup/',
            '/.git/',
            '/.svn/',
            '/web.config',
            '/.htaccess',
            '/phpinfo.php',
            '/test.php',
            '/install.php',
            '/wp-config.php',
            '/readme.html',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/uploads/',
            '/upload/',
            '/images/',
            '/static/',
            '/assets/',
            '/public/',
            '/tmp/',
            '/temp/',
            '/cache/',
            '/logs/',
            '/log/',
            '/database/',
            '/db/',
            '/sql/',
            '/backup.sql',
            '/dump.sql',
            '/data.sql',
            '/db.sql'
        ]
        
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8888: 'HTTP',
            9000: 'HTTP',
            27017: 'MongoDB'
        }
        
        self.waf_fingerprints = {
            'Cloudflare': {
                'headers': ['Server: cloudflare', 'Server: Cloudflare', 'CF-RAY:', 'cf-request-id:'],
                'keywords': ['cloudflare', 'Cloudflare'],
                'status_codes': [403, 429]
            },
            'AWS WAF': {
                'headers': ['X-Amz-Waf-Result:'],
                'keywords': ['AWS WAF', 'amazonaws'],
                'status_codes': [403]
            },
            'ModSecurity': {
                'headers': ['Server: ModSecurity', 'X-Mod-Security:'],
                'keywords': ['ModSecurity'],
                'status_codes': [403]
            },
            'Sucuri WAF': {
                'headers': ['Server: Sucuri/Cloudproxy', 'X-Sucuri-ID:'],
                'keywords': ['Sucuri'],
                'status_codes': [403]
            },
            'Akamai': {
                'headers': ['Server: AkamaiGHost'],
                'keywords': ['Akamai'],
                'status_codes': [403]
            },
            'Fastly': {
                'headers': ['Server: Fastly'],
                'keywords': ['Fastly'],
                'status_codes': [403]
            },
            'Incapsula': {
                'headers': ['X-Incapsula-Request-ID:'],
                'keywords': ['Incapsula'],
                'status_codes': [403]
            },
            'Tencent Cloud WAF': {
                'headers': ['Server: tencent', 'X-Tencent-WAF:'],
                'keywords': ['Tencent Cloud WAF'],
                'status_codes': [403]
            },
            'Aliyun WAF': {
                'headers': ['Server: AliyunWAF', 'X-Aliyun-WAF:'],
                'keywords': ['Aliyun WAF'],
                'status_codes': [403]
            }
        }
    
    def identify_server(self, headers, content):
        detected_servers = []
        content_lower = content.lower() if content else ''
        
        for server_name, fingerprint in self.server_fingerprints.items():
            if self._match_fingerprint(headers, content_lower, fingerprint):
                detected_servers.append(server_name)
        
        return detected_servers
    
    def identify_cms(self, headers, content, url):
        detected_cms = []
        content_lower = content.lower() if content else ''
        url_lower = url.lower() if url else ''
        
        for cms_name, fingerprint in self.cms_fingerprints.items():
            if self._match_fingerprint(headers, content_lower, fingerprint):
                detected_cms.append(cms_name)
            elif self._match_path(url_lower, fingerprint.get('paths', [])):
                detected_cms.append(cms_name)
        
        return detected_cms
    
    def _match_fingerprint(self, headers, content, fingerprint):
        headers_str = str(headers).lower() if headers else ''
        
        for header in fingerprint.get('headers', []):
            if header.lower() in headers_str:
                return True
        
        for keyword in fingerprint.get('keywords', []):
            if keyword.lower() in content:
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