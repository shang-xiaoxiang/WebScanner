import requests
import socket
import dns.resolver
from urllib.parse import urlparse

class AssetCollector:
    def __init__(self):
        pass
    
    def detect_cdn(self, target):
        """检测是否使用CDN"""
        try:
            # 提取域名
            parsed_url = urlparse(target)
            domain = parsed_url.netloc if parsed_url.netloc else target
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # 移除 www 前缀
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # 多DNS服务器解析
            dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '208.67.220.220']
            ips = set()
            
            for server in dns_servers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [server]
                    answers = resolver.resolve(domain, 'A')
                    for rdata in answers:
                        ips.add(rdata.address)
                except Exception:
                    pass
            
            # 检查响应头
            cdn_headers = ['Via', 'X-CDN', 'X-Cache', 'X-Cache-Hits', 'X-Edge-Origin', 'X-Content-Delivery-Network']
            cdn_detected = False
            
            try:
                url = target if parsed_url.scheme else f"http://{target}"
                response = requests.get(url, timeout=5, allow_redirects=True)
                for header in cdn_headers:
                    if header in response.headers:
                        cdn_detected = True
                        break
            except Exception:
                pass
            
            # 如果解析到多个IP或响应头中有CDN信息，则认为使用了CDN
            if len(ips) > 1 or cdn_detected:
                return {
                    'cdn': True,
                    'ips': list(ips),
                    'message': '穿透 CDN 需额外操作'
                }
            else:
                return {
                    'cdn': False,
                    'ips': list(ips),
                    'message': '未检测到 CDN'
                }
        except Exception:
            return {
                'cdn': False,
                'ips': [],
                'message': 'CDN 检测失败'
            }
    
    def detect_vulnerabilities(self, target):
        """简易漏洞探测"""
        vulnerabilities = []
        
        # 检测 WordPress 低版本漏洞
        try:
            url = target if urlparse(target).scheme else f"http://{target}"
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            # 检测 WordPress 版本
            if 'wp-content' in response.text or 'wordpress' in response.text.lower():
                # 检测 wp-login.php 是否可访问
                login_url = url.rstrip('/') + '/wp-login.php'
                login_response = requests.get(login_url, timeout=5)
                if login_response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'WordPress',
                        'severity': 'medium',
                        'message': 'WordPress 登录页面可访问，建议检查版本是否存在漏洞'
                    })
        except Exception:
            pass
        
        # 检测 ThinkPHP 5.0 漏洞
        try:
            url = target if urlparse(target).scheme else f"http://{target}"
            test_url = url.rstrip('/') + '/index.php?s=/Index/\	hink\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'
            response = requests.get(test_url, timeout=5)
            if 'PHP Version' in response.text:
                vulnerabilities.append({
                    'type': 'ThinkPHP 5.0',
                    'severity': 'high',
                    'message': '存在 ThinkPHP 5.0 远程代码执行漏洞'
                })
        except Exception:
            pass
        
        # 检测 phpMyAdmin 漏洞
        try:
            url = target if urlparse(target).scheme else f"http://{target}"
            phpmyadmin_url = url.rstrip('/') + '/phpmyadmin/'
            response = requests.get(phpmyadmin_url, timeout=5)
            if response.status_code == 200 and 'phpMyAdmin' in response.text:
                vulnerabilities.append({
                    'type': 'phpMyAdmin',
                    'severity': 'medium',
                    'message': 'phpMyAdmin 可访问，建议检查版本是否存在漏洞'
                })
        except Exception:
            pass
        
        # 检测 .env 文件泄露
        try:
            url = target if urlparse(target).scheme else f"http://{target}"
            env_url = url.rstrip('/') + '/.env'
            response = requests.get(env_url, timeout=5)
            if response.status_code == 200 and ('APP_KEY' in response.text or 'DB_PASSWORD' in response.text):
                vulnerabilities.append({
                    'type': 'Env File',
                    'severity': 'high',
                    'message': '.env 文件可访问，可能泄露敏感信息'
                })
        except Exception:
            pass
        
        return vulnerabilities
