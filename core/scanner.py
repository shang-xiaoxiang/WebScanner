import socket
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from core.fingerprint import FingerprintDB
import time
import re
import whois

# 尝试导入异步库
try:
    import asyncio
    import aiohttp
    HAS_ASYNC = True
except ImportError:
    HAS_ASYNC = False

class WebScanner:
    def __init__(self):
        self.fingerprint_db = FingerprintDB()
        self.timeout = 5
        self.max_threads = 50
        self.port_range = "1-1000"
        self.scan_strategy = "tcp"
        self.scan_rate = 100
        self.custom_ports = []
        self.custom_dictionary = []
    
    def set_custom_dictionary(self, dictionary):
        """设置自定义敏感目录字典"""
        if isinstance(dictionary, list):
            self.custom_dictionary = dictionary
    
    def load_dictionary_from_file(self, file_path):
        """从文件加载敏感目录字典"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                paths = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            self.custom_dictionary = paths
            return True
        except Exception:
            return False
    
    def scan(self, target):
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
            
            http_result = self._scan_http(url)
            result.update(http_result)
            
            # 子域名探测
            subdomains = self._detect_subdomains(target)
            result['subdomains'] = subdomains
            
            # CDN 识别
            cdn_info = self._detect_cdn(url)
            result['cdn_info'] = cdn_info
            
            # 漏洞初步检测
            vulnerabilities = self._detect_vulnerabilities(url)
            result['vulnerabilities'] = vulnerabilities
            
            # WHOIS 信息查询
            whois_info = self._get_whois_info(target)
            result['whois_info'] = whois_info
        
        # 扫描端口
        ports = self._scan_ports(result['ip'])
        result['open_ports'] = ports
        
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
                    except Exception:
                        pass
                
                middleware = self.fingerprint_db.identify_middleware(headers, content, open_port_numbers, status_code, cookies, tls_info)
                result['middleware'] = middleware
            except Exception:
                pass
        
        return result
    
    async def _async_scan_sensitive_paths(self, base_url):
        # 使用自定义字典或默认字典
        if self.custom_dictionary:
            sensitive_paths = self.custom_dictionary
        else:
            sensitive_paths = self.fingerprint_db.get_sensitive_paths()
        
        found_paths = []
        
        # 控制并发数
        max_concurrency = 20
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def bounded_check_path(session, path):
            async with semaphore:
                return await self._async_check_path(session, base_url, path)
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in sensitive_paths:
                task = bounded_check_path(session, path)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if result:
                    found_paths.append({
                        'path': sensitive_paths[i],
                        'status': result
                    })
        
        return found_paths
    
    async def _async_check_path(self, session, base_url, path):
        try:
            url = base_url.rstrip('/') + path
            async with session.get(url, timeout=3, allow_redirects=False) as response:
                # 检查状态码
                status_code = response.status
                
                # 检查响应内容，判断是否为 404 统一页面
                content = await response.text()
                
                # 智能过滤：排除 404 统一页面
                if status_code == 404:
                    # 检查是否为真实的 404 页面
                    if '404' in content.lower() or 'not found' in content.lower():
                        return None
                
                if status_code == 200:
                    return 'accessible'
                elif status_code == 403:
                    return 'forbidden'
                elif status_code == 301:
                    return 'permanent_redirect'
                elif status_code == 302:
                    return 'temporary_redirect'
            return None
        except Exception:
            return None
    
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
    
    def _parse_port_range(self, port_range):
        """解析端口范围字符串，返回端口列表"""
        ports = []
        try:
            if ',' in port_range:
                # 处理端口列表，如 "80,443,8080"
                for port_str in port_range.split(','):
                    port = int(port_str.strip())
                    if 1 <= port <= 65535:
                        ports.append(port)
            elif '-' in port_range:
                # 处理端口范围，如 "1-1000"
                start, end = port_range.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                if 1 <= start_port <= end_port <= 65535:
                    ports.extend(range(start_port, end_port + 1))
            else:
                # 处理单个端口
                port = int(port_range.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
        except Exception:
            pass
        
        # 如果没有指定端口，使用默认端口
        if not ports:
            ports = list(self.fingerprint_db.get_common_ports().keys())
        
        return ports
    
    def _scan_ports(self, ip):
        if not ip:
            return []
        
        open_ports = []
        common_ports = self.fingerprint_db.get_common_ports()
        
        # 解析端口范围
        ports_to_scan = self._parse_port_range(self.port_range)
        
        # 如果有自定义端口，添加到扫描列表
        if self.custom_ports:
            ports_to_scan.extend(self.custom_ports)
            # 去重
            ports_to_scan = list(set(ports_to_scan))
        
        # 控制扫描速率
        scan_interval = 1.0 / self.scan_rate if self.scan_rate > 0 else 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, ip, port, self.scan_strategy): port for port in ports_to_scan}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        service = common_ports.get(port, 'Unknown')
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'status': 'open'
                        })
                except Exception as e:
                    pass
                
                # 控制扫描速率
                if scan_interval > 0:
                    time.sleep(scan_interval)
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def _check_port(self, ip, port, strategy='tcp'):
        try:
            if strategy == 'tcp':
                # TCP 连接扫描
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return result == 0
            elif strategy == 'syn':
                # SYN 扫描 (需要 root 权限)
                try:
                    import scapy.all as scapy
                    packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags='S')
                    response = scapy.sr1(packet, timeout=self.timeout, verbose=False)
                    if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags & 0x12:
                        # 收到 SYN-ACK
                        return True
                except ImportError:
                    # 如果没有 scapy，回退到 TCP 扫描
                    return self._check_port(ip, port, 'tcp')
                except Exception:
                    pass
            elif strategy == 'udp':
                # UDP 扫描
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(b'', (ip, port))
                    # 尝试接收响应
                    data, addr = sock.recvfrom(1024)
                    return True
                except socket.timeout:
                    # 没有响应可能表示端口开放
                    return True
                except socket.error:
                    # 收到 ICMP 端口不可达
                    return False
                finally:
                    sock.close()
            return False
        except Exception:
            return False
    
    def _scan_http(self, url):
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
            result['content_length'] = len(content)
            
            servers = self.fingerprint_db.identify_server(headers, content, status_code, cookies, tls_info)
            result['server_info'] = servers
            
            cms_list = self.fingerprint_db.identify_cms(headers, content, url, status_code, cookies, tls_info)
            result['cms_info'] = cms_list
            
            waf_list = self.fingerprint_db.identify_waf(headers, content, status_code)
            result['waf_info'] = waf_list
            
            languages = self.fingerprint_db.identify_programming_language(headers, content, status_code, cookies, tls_info)
            result['programming_languages'] = languages
            
            # 暂时传递空列表，后续会从端口扫描结果中获取
            middleware = self.fingerprint_db.identify_middleware(headers, content, [], status_code, cookies, tls_info)
            result['middleware'] = middleware
            
            sensitive_paths = self._scan_sensitive_paths(url)
            result['sensitive_paths'] = sensitive_paths
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result
    
    def _scan_sensitive_paths(self, base_url):
        if HAS_ASYNC:
            try:
                # 使用异步扫描提高效率
                return asyncio.run(self._async_scan_sensitive_paths(base_url))
            except Exception:
                # 异步扫描失败时回退到同步扫描
                pass
        
        # 使用同步扫描
        # 使用自定义字典或默认字典
        if self.custom_dictionary:
            sensitive_paths = self.custom_dictionary
        else:
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
            
            # 检查状态码
            status_code = response.status_code
            
            # 检查响应内容，判断是否为 404 统一页面
            content = response.text
            
            # 智能过滤：排除 404 统一页面
            if status_code == 404:
                # 检查是否为真实的 404 页面
                if '404' in content.lower() or 'not found' in content.lower():
                    return None
            
            if status_code == 200:
                return 'accessible'
            elif status_code == 403:
                return 'forbidden'
            elif status_code == 301:
                return 'permanent_redirect'
            elif status_code == 302:
                return 'temporary_redirect'
            
            return None
        except requests.exceptions.RequestException:
            return None
    
    def _detect_subdomains(self, target):
        """子域名探测"""
        subdomains = []
        common_subdomains = ['www', 'api', 'admin', 'test', 'staging', 'dev', 'beta', 'blog', 'mail', 'ftp', 'sftp', 'cdn', 'static', 'images', 'files', 'download', 'upload', 'backup', 'database', 'db', 'mysql', 'postgres', 'redis', 'mongodb', 'elastic', 'search', 'monitor', 'metrics', 'health', 'status', 'docs', 'documentation', 'help', 'support', 'faq', 'about', 'contact', 'feedback', 'news', 'newsletter', 'subscribe', 'unsubscribe', 'rss', 'feed', 'sitemap', 'robots', 'humans', 'crossdomain', 'clientaccesspolicy']
        
        # 提取域名
        parsed_url = urlparse(target)
        domain = parsed_url.netloc if parsed_url.netloc else target
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 简单的字典爆破
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub for sub in common_subdomains}
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        subdomains.append(f"{subdomain}.{domain}")
                except Exception:
                    pass
        
        return subdomains
    
    def _check_subdomain(self, subdomain):
        """检查子域名是否存在"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except Exception:
            return False
    
    def _detect_cdn(self, url):
        """CDN 识别"""
        cdn_providers = {
            'Cloudflare': ['cloudflare', 'cf-', 'CF-'],
            'Akamai': ['akamai', 'akamaiedge', 'akamaitechnologies'],
            'Fastly': ['fastly', 'fastly.net'],
            'AWS CloudFront': ['cloudfront', 'amazonaws'],
            'Google Cloud CDN': ['googleusercontent', 'gstatic'],
            'Microsoft Azure CDN': ['azureedge', 'msecnd.net'],
            'Cloudinary': ['cloudinary'],
            'KeyCDN': ['keycdn'],
            'Bunny CDN': ['b-cdn.net'],
            'CDNetworks': ['cdnetworks', 'cdngc.net'],
            'ChinaCache': ['chinacache'],
            'Alibaba Cloud CDN': ['alibabacdn', 'aliyuncs'],
            'Tencent Cloud CDN': ['tcdn', 'qcloudcdn']
        }
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # 解析域名的 IP
            ip = socket.gethostbyname(domain)
            
            # 检查响应头
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = dict(response.headers)
            headers_str = str(headers).lower()
            
            # 检查 CDN 特征
            detected_cdn = []
            for provider, keywords in cdn_providers.items():
                for keyword in keywords:
                    if keyword.lower() in headers_str or keyword.lower() in ip:
                        detected_cdn.append(provider)
                        break
            
            return detected_cdn
        except Exception:
            return []
    
    def _detect_vulnerabilities(self, url):
        """漏洞初步检测"""
        vulnerabilities = []
        
        # SQL 注入检测
        test_payloads = ["' OR 1=1 --", "' OR '1'='1", "\' OR \'1\'=\'1"]
        for payload in test_payloads:
            test_url = f"{url}?id={payload}" if '?' in url else f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, allow_redirects=True)
                content = response.text.lower()
                if 'syntax error' in content or 'mysql' in content or 'postgresql' in content or 'sqlite' in content:
                    vulnerabilities.append('SQL 注入可能')
                    break
            except Exception:
                pass
        
        # XSS 检测
        xss_payload = "<script>alert('XSS')</script>"
        test_url = f"{url}?q={xss_payload}" if '?' in url else f"{url}?q={xss_payload}"
        try:
            response = requests.get(test_url, timeout=self.timeout, allow_redirects=True)
            content = response.text
            if xss_payload in content:
                vulnerabilities.append('XSS 可能')
        except Exception:
            pass
        
        # 弱口令检测（仅提示）
        common_login_paths = ['/admin/', '/login/', '/signin/', '/auth/', '/wp-login.php', '/administrator/']
        for path in common_login_paths:
            test_url = url.rstrip('/') + path
            try:
                response = requests.get(test_url, timeout=self.timeout, allow_redirects=True)
                if response.status_code == 200 and ('login' in response.text.lower() or 'sign in' in response.text.lower()):
                    vulnerabilities.append('弱口令风险（登录页面存在）')
                    break
            except Exception:
                pass
        
        return vulnerabilities
    
    def _get_whois_info(self, target):
        """WHOIS 信息查询"""
        try:
            # 提取域名
            parsed_url = urlparse(target)
            domain = parsed_url.netloc if parsed_url.netloc else target
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # 移除 www 前缀
            if domain.startswith('www.'):
                domain = domain[4:]
            
            w = whois.whois(domain)
            whois_info = {
                'domain': w.domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers
            }
            return whois_info
        except Exception:
            return {}
    
    def quick_scan(self, target):
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