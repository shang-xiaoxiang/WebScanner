import requests
import time
from urllib.parse import urlparse
from core.scanner.port_scanner import PortScanner
from core.scanner.dir_scanner import DirScanner
from core.scanner.fingerprint import FingerprintDB
from core.collector.subdomain import SubdomainCollector
from core.collector.whois import WhoisCollector
from core.collector.asset import AssetCollector
from core.utils.log_utils import setup_logger

logger = setup_logger('webscanner')

class WebScanner:
    def __init__(self):
        self.fingerprint_db = FingerprintDB()
        self.port_scanner = PortScanner()
        self.dir_scanner = DirScanner()
        self.subdomain_collector = SubdomainCollector()
        self.whois_collector = WhoisCollector()
        self.asset_collector = AssetCollector()
        self.timeout = 5
    
    def set_custom_dictionary(self, dictionary):
        """设置自定义敏感目录字典"""
        self.dir_scanner.set_custom_dictionary(dictionary)
    
    def load_dictionary_from_file(self, file_path):
        """从文件加载敏感目录字典"""
        return self.dir_scanner.load_dictionary_from_file(file_path)
    
    def scan(self, target):
        logger.info(f'开始扫描目标: {target}')
        result = {
            'target': target,
            'ip': self._resolve_ip(target),
            'open_ports': [],
            'server_info': [],
            'cms_info': [],
            'waf_info': [],
            'programming_languages': [],
            'middleware': [],
            'sensitive_paths': [],
            'subdomains': [],
            'cdn_info': [],
            'vulnerabilities': [],
            'whois_info': {},
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        url = self._normalize_url(target)
        if url:
            result['url'] = url
            logger.info(f'标准化URL: {url}')
            
            http_result = self._scan_http(url)
            result.update(http_result)
            
            # 子域名探测
            logger.info('开始子域名探测')
            subdomains = self.subdomain_collector.detect(target)
            result['subdomains'] = subdomains
            logger.info(f'发现子域名: {len(subdomains)}个')
            
            # CDN 识别
            logger.info('开始CDN识别')
            cdn_info = self.asset_collector.detect_cdn(url)
            result['cdn_info'] = cdn_info
            if cdn_info['cdn']:
                logger.info(f'检测到CDN: {cdn_info}')
            
            # 漏洞初步检测
            logger.info('开始漏洞初步检测')
            vulnerabilities = self.asset_collector.detect_vulnerabilities(url)
            result['vulnerabilities'] = vulnerabilities
            if vulnerabilities:
                logger.warning(f'发现可能的漏洞: {vulnerabilities}')
            
            # WHOIS 信息查询
            logger.info('开始WHOIS信息查询')
            whois_info = self.whois_collector.get_info(target)
            result['whois_info'] = whois_info
        
        # 扫描端口
        logger.info('开始端口扫描')
        ports = self.port_scanner.scan(result['ip'], self.fingerprint_db.get_common_ports())
        result['open_ports'] = ports
        logger.info(f'发现开放端口: {len(ports)}个')
        
        # 从开放端口更新中间件识别
        open_port_numbers = [port['port'] for port in ports]
        if url and open_port_numbers:
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                headers = dict(response.headers)
                content = response.text
                status_code = response.status_code
                cookies = dict(response.cookies)
                
                # 获取TLS证书信息
                tls_info = {}
                if url.startswith('https://'):
                    try:
                        import ssl
                        import socket
                        parsed_url = urlparse(url)
                        context = ssl.create_default_context()
                        with socket.create_connection((parsed_url.netloc, 443), timeout=self.timeout) as sock:
                            with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                                cert = ssock.getpeercert()
                                if cert:
                                    # 提取证书信息
                                    if 'subject' in cert:
                                        for item in cert['subject']:
                                            if item[0][0] == 'commonName':
                                                tls_info['common_name'] = item[0][1]
                                    if 'issuer' in cert:
                                        for item in cert['issuer']:
                                            if item[0][0] == 'organizationName':
                                                tls_info['issuer'] = item[0][1]
                    except Exception as e:
                        logger.debug(f'获取TLS证书信息失败: {e}')
                
                middleware = self.fingerprint_db.identify_middleware(headers, content, open_port_numbers, status_code, cookies, tls_info)
                result['middleware'] = middleware
                if middleware:
                    logger.info(f'识别到中间件: {middleware}')
            except Exception as e:
                logger.debug(f'更新中间件识别失败: {e}')
        
        logger.info(f'扫描完成，目标: {target}')
        return result
    
    def _resolve_ip(self, target):
        try:
            if self._is_ip(target):
                return target
            import socket
            return socket.gethostbyname(target)
        except Exception:
            return None
    
    def _is_ip(self, target):
        try:
            import socket
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
    
    def _scan_http(self, url):
        logger.info(f'开始HTTP扫描: {url}')
        result = {
            'server_info': [],
            'cms_info': [],
            'waf_info': [],
            'programming_languages': [],
            'middleware': [],
            'sensitive_paths': []
        }
        
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = dict(response.headers)
            content = response.text
            status_code = response.status_code
            cookies = dict(response.cookies)
            logger.info(f'HTTP响应状态码: {status_code}')
            
            # 获取TLS证书信息
            tls_info = {}
            if url.startswith('https://'):
                try:
                    import ssl
                    import socket
                    parsed_url = urlparse(url)
                    context = ssl.create_default_context()
                    with socket.create_connection((parsed_url.netloc, 443), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                            cert = ssock.getpeercert()
                            if cert:
                                # 提取证书信息
                                if 'subject' in cert:
                                    for item in cert['subject']:
                                        if item[0][0] == 'commonName':
                                            tls_info['common_name'] = item[0][1]
                                if 'issuer' in cert:
                                    for item in cert['issuer']:
                                        if item[0][0] == 'organizationName':
                                            tls_info['issuer'] = item[0][1]
                    logger.debug('成功获取TLS证书信息')
                except Exception as e:
                    logger.debug(f'获取TLS证书信息失败: {e}')
            
            result['status_code'] = status_code
            result['content_length'] = len(content)
            
            servers = self.fingerprint_db.identify_server(headers, content, status_code, cookies, tls_info)
            result['server_info'] = servers
            if servers:
                logger.info(f'识别到服务器: {servers}')
            
            cms_list = self.fingerprint_db.identify_cms(headers, content, url, status_code, cookies, tls_info)
            result['cms_info'] = cms_list
            if cms_list:
                logger.info(f'识别到CMS: {cms_list}')
            
            waf_list = self.fingerprint_db.identify_waf(headers, content, status_code)
            result['waf_info'] = waf_list
            if waf_list:
                logger.info(f'识别到WAF: {waf_list}')
            
            languages = self.fingerprint_db.identify_programming_language(headers, content, status_code, cookies, tls_info)
            result['programming_languages'] = languages
            if languages:
                logger.info(f'识别到编程语言: {languages}')
            
            # 暂时传递空列表，后续会从端口扫描结果中获取
            middleware = self.fingerprint_db.identify_middleware(headers, content, [], status_code, cookies, tls_info)
            result['middleware'] = middleware
            
            logger.info('开始敏感目录扫描')
            sensitive_paths = self.dir_scanner.scan(url, self.fingerprint_db.get_sensitive_paths())
            result['sensitive_paths'] = sensitive_paths
            logger.info(f'发现敏感目录: {len(sensitive_paths)}个')
            
        except requests.exceptions.RequestException as e:
            logger.error(f'HTTP扫描失败: {e}')
            result['error'] = str(e)
        
        return result
    

    
    def set_scan_mode(self, mode, **kwargs):
        """设置扫描模式
        
        Args:
            mode: 扫描模式，可选值：'quick', 'full', 'custom'
            **kwargs: 自定义扫描参数
                - port_range: 端口范围
                - dictionary_level: 字典级别 ('basic', 'high', 'full')
                - concurrency: 并发数
                - timeout: 超时时间
                - scan_strategy: 扫描策略 ('tcp', 'syn', 'udp')
        """
        if mode == 'quick':
            # 快速扫描：仅扫 TOP100 端口 + 基础字典 + 核心指纹，超时时间 1s，并发数 30
            self.port_scanner.port_range = '1-1000'  # 使用TOP1000端口作为快速扫描
            self.port_scanner.timeout = 1
            self.port_scanner.concurrency = 30
            self.dir_scanner.dictionary_level = 'basic'
            self.dir_scanner.timeout = 1
            self.dir_scanner.concurrency = 30
        elif mode == 'full':
            # 完整扫描：扫 TOP1000 端口 + 全量字典 + 全维度指纹，超时时间 3s，并发数 50
            self.port_scanner.port_range = '1-65535'  # 全端口
            self.port_scanner.timeout = 3
            self.port_scanner.concurrency = 50
            self.dir_scanner.dictionary_level = 'full'
            self.dir_scanner.timeout = 3
            self.dir_scanner.concurrency = 50
        elif mode == 'custom':
            # 自定义扫描：用户可自由配置
            if 'port_range' in kwargs:
                self.port_scanner.port_range = kwargs['port_range']
            if 'dictionary_level' in kwargs:
                self.dir_scanner.dictionary_level = kwargs['dictionary_level']
            if 'concurrency' in kwargs:
                self.port_scanner.concurrency = kwargs['concurrency']
                self.dir_scanner.concurrency = kwargs['concurrency']
            if 'timeout' in kwargs:
                self.port_scanner.timeout = kwargs['timeout']
                self.dir_scanner.timeout = kwargs['timeout']
                self.timeout = kwargs['timeout']
            if 'scan_strategy' in kwargs:
                self.port_scanner.scan_strategy = kwargs['scan_strategy']
    
    def quick_scan(self, target):
        """快速扫描"""
        # 设置快速扫描模式
        self.set_scan_mode('quick')
        
        result = {
            'target': target,
            'ip': self._resolve_ip(target),
            'server_info': [],
            'cms_info': [],
            'waf_info': [],
            'programming_languages': [],
            'middleware': [],
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
                cookies = dict(response.cookies)
                
                # 获取TLS证书信息
                tls_info = {}
                if url.startswith('https://'):
                    try:
                        import ssl
                        import socket
                        parsed_url = urlparse(url)
                        context = ssl.create_default_context()
                        with socket.create_connection((parsed_url.netloc, 443), timeout=self.timeout) as sock:
                            with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                                cert = ssock.getpeercert()
                                if cert:
                                    # 提取证书信息
                                    if 'subject' in cert:
                                        for item in cert['subject']:
                                            if item[0][0] == 'commonName':
                                                tls_info['common_name'] = item[0][1]
                                    if 'issuer' in cert:
                                        for item in cert['issuer']:
                                            if item[0][0] == 'organizationName':
                                                tls_info['issuer'] = item[0][1]
                    except Exception:
                        pass
                
                result['status_code'] = status_code
                
                servers = self.fingerprint_db.identify_server(headers, content, status_code, cookies, tls_info)
                result['server_info'] = servers
                
                cms_list = self.fingerprint_db.identify_cms(headers, content, url, status_code, cookies, tls_info)
                result['cms_info'] = cms_list
                
                waf_list = self.fingerprint_db.identify_waf(headers, content, status_code)
                result['waf_info'] = waf_list
                
                languages = self.fingerprint_db.identify_programming_language(headers, content, status_code, cookies, tls_info)
                result['programming_languages'] = languages
                
                middleware = self.fingerprint_db.identify_middleware(headers, content, [], status_code, cookies, tls_info)
                result['middleware'] = middleware
                
            except requests.exceptions.RequestException as e:
                result['error'] = str(e)
        
        return result
