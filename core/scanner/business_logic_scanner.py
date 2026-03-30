"""
真实业务逻辑漏洞检测模块
自动识别网站功能并针对性扫描业务逻辑漏洞
"""

import requests
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from core.utils.log_utils import setup_logger

logger = setup_logger('business_logic_scanner')


class BusinessLogicScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # 常见的登录表单特征
        self.login_patterns = [
            r'login',
            r'signin',
            r'password',
            r'username',
            r'auth',
            r'登录',
            r'密码',
            r'用户名'
        ]
        
        # 常见的上传表单特征
        self.upload_patterns = [
            r'upload',
            r'file',
            r'attachment',
            r'上传',
            r'文件'
        ]
        
        # 常见的搜索框特征
        self.search_patterns = [
            r'search',
            r'query',
            r'keyword',
            r'搜索',
            r'查询'
        ]
        
        # 常见的后台管理特征
        self.admin_patterns = [
            r'admin',
            r'administrator',
            r'manage',
            r'backend',
            r'panel',
            r'后台',
            r'管理'
        ]
        
        # 常见的验证码特征
        self.captcha_patterns = [
            r'captcha',
            r'verify',
            r'code',
            r'验证码',
            r'验证'
        ]
    
    def scan(self, url: str) -> Dict:
        """
        扫描业务逻辑漏洞
        
        Args:
            url: 目标URL
            
        Returns:
            包含业务逻辑漏洞检测结果的字典
        """
        logger.info(f'开始业务逻辑漏洞扫描: {url}')
        
        result = {
            'login_vulnerabilities': [],
            'upload_vulnerabilities': [],
            'xss_vulnerabilities': [],
            'admin_vulnerabilities': [],
            'captcha_vulnerabilities': [],
            'business_logic_issues': []
        }
        
        try:
            # 识别网站功能
            features = self._identify_features(url)
            logger.info(f'识别到的功能: {features}')
            
            # 针对性扫描
            if features.get('login'):
                result['login_vulnerabilities'] = self._scan_login_vulnerabilities(url)
            
            if features.get('upload'):
                result['upload_vulnerabilities'] = self._scan_upload_vulnerabilities(url)
            
            if features.get('search'):
                result['xss_vulnerabilities'] = self._scan_xss_vulnerabilities(url)
            
            if features.get('admin'):
                result['admin_vulnerabilities'] = self._scan_admin_vulnerabilities(url)
            
            if features.get('captcha'):
                result['captcha_vulnerabilities'] = self._scan_captcha_vulnerabilities(url)
            
            # 通用业务逻辑漏洞检测
            result['business_logic_issues'] = self._scan_general_business_logic(url)
            
            logger.info('业务逻辑漏洞扫描完成')
            return result
            
        except Exception as e:
            logger.error(f'业务逻辑漏洞扫描失败: {str(e)}')
            return result
    
    def _identify_features(self, url: str) -> Dict:
        """识别网站功能"""
        features = {
            'login': False,
            'upload': False,
            'search': False,
            'admin': False,
            'captcha': False
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            content = response.text.lower()
            
            # 检查登录功能
            for pattern in self.login_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    features['login'] = True
                    break
            
            # 检查上传功能
            for pattern in self.upload_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    features['upload'] = True
                    break
            
            # 检查搜索功能
            for pattern in self.search_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    features['search'] = True
                    break
            
            # 检查后台管理
            for pattern in self.admin_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    features['admin'] = True
                    break
            
            # 检查验证码
            for pattern in self.captcha_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    features['captcha'] = True
                    break
            
            # 检查表单
            forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
            for form in forms:
                if 'type="password"' in form:
                    features['login'] = True
                if 'type="file"' in form:
                    features['upload'] = True
                if 'type="text"' in form and ('search' in form or 'query' in form):
                    features['search'] = True
            
        except Exception as e:
            logger.error(f'识别网站功能失败: {str(e)}')
        
        return features
    
    def _scan_login_vulnerabilities(self, url: str) -> List[Dict]:
        """扫描登录漏洞"""
        vulnerabilities = []
        
        try:
            # 测试弱口令
            weak_passwords = ['admin', 'password', '123456', 'admin123']
            
            for password in weak_passwords:
                try:
                    login_data = {
                        'username': 'admin',
                        'password': password
                    }
                    
                    response = self.session.post(url, data=login_data, timeout=self.timeout)
                    
                    if response.status_code == 200 and 'success' in response.text.lower():
                        vulnerabilities.append({
                            'type': 'weak_password',
                            'severity': 'high',
                            'description': f'发现弱口令: admin/{password}',
                            'url': url
                        })
                        break
                        
                except Exception:
                    continue
            
            # 测试SQL注入
            sql_payloads = [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' UNION SELECT NULL,NULL,NULL--",
                "admin'--"
            ]
            
            for payload in sql_payloads:
                try:
                    login_data = {
                        'username': payload,
                        'password': 'test'
                    }
                    
                    response = self.session.post(url, data=login_data, timeout=self.timeout)
                    
                    if response.status_code == 200 and ('error' in response.text.lower() or 'mysql' in response.text.lower()):
                        vulnerabilities.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'description': f'可能存在SQL注入漏洞',
                            'url': url,
                            'payload': payload
                        })
                        break
                        
                except Exception:
                    continue
            
        except Exception as e:
            logger.error(f'扫描登录漏洞失败: {str(e)}')
        
        return vulnerabilities
    
    def _scan_upload_vulnerabilities(self, url: str) -> List[Dict]:
        """扫描文件上传漏洞"""
        vulnerabilities = []
        
        try:
            # 测试恶意文件上传
            test_files = [
                {'name': 'test.php', 'content': '<?php phpinfo(); ?>'},
                {'name': 'test.jsp', 'content': '<% out.println("test"); %>'},
                {'name': 'test.asp', 'content': '<% Response.Write("test") %>'},
                {'name': 'test.html', 'content': '<script>alert("XSS")</script>'}
            ]
            
            for test_file in test_files:
                try:
                    files = {'file': (test_file['name'], test_file['content'])}
                    response = self.session.post(url, files=files, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'file_upload',
                            'severity': 'high',
                            'description': f'可能存在文件上传漏洞，允许上传 {test_file["name"]}',
                            'url': url
                        })
                        break
                        
                except Exception:
                    continue
            
            # 测试文件类型绕过
            bypass_files = [
                {'name': 'test.php.jpg', 'content': '<?php phpinfo(); ?>'},
                {'name': 'test.php%00.jpg', 'content': '<?php phpinfo(); ?>'},
                {'name': 'test.php.', 'content': '<?php phpinfo(); ?>'}
            ]
            
            for test_file in bypass_files:
                try:
                    files = {'file': (test_file['name'], test_file['content'])}
                    response = self.session.post(url, files=files, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'file_type_bypass',
                            'severity': 'medium',
                            'description': f'可能存在文件类型绕过漏洞',
                            'url': url
                        })
                        break
                        
                except Exception:
                    continue
            
        except Exception as e:
            logger.error(f'扫描文件上传漏洞失败: {str(e)}')
        
        return vulnerabilities
    
    def _scan_xss_vulnerabilities(self, url: str) -> List[Dict]:
        """扫描XSS漏洞"""
        vulnerabilities = []
        
        try:
            # 测试反射型XSS
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                '"><img src=x onerror=alert("XSS")>'
            ]
            
            for payload in xss_payloads:
                try:
                    search_params = {'q': payload, 'search': payload, 'query': payload}
                    
                    for param, value in search_params.items():
                        try:
                            test_url = f"{url}?{param}={value}"
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            if payload in response.text:
                                vulnerabilities.append({
                                    'type': 'reflected_xss',
                                    'severity': 'medium',
                                    'description': f'发现反射型XSS漏洞',
                                    'url': test_url,
                                    'payload': payload
                                })
                                break
                                
                        except Exception:
                            continue
                    
                    if vulnerabilities:
                        break
                        
                except Exception:
                    continue
            
        except Exception as e:
            logger.error(f'扫描XSS漏洞失败: {str(e)}')
        
        return vulnerabilities
    
    def _scan_admin_vulnerabilities(self, url: str) -> List[Dict]:
        """扫描管理员后台漏洞"""
        vulnerabilities = []
        
        try:
            # 常见的管理员后台路径
            admin_paths = [
                '/admin',
                '/administrator',
                '/admin.php',
                '/admin.asp',
                '/admin.aspx',
                '/admin/index.php',
                '/backend',
                '/manage',
                '/panel',
                '/console',
                '/dashboard'
            ]
            
            for path in admin_paths:
                try:
                    test_url = urljoin(url, path)
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # 检查是否需要认证
                        if 'login' not in response.text.lower() and 'password' not in response.text.lower():
                            vulnerabilities.append({
                                'type': 'unauthorized_access',
                                'severity': 'high',
                                'description': f'发现未授权访问的管理员后台: {path}',
                                'url': test_url
                            })
                        else:
                            vulnerabilities.append({
                                'type': 'admin_panel_found',
                                'severity': 'info',
                                'description': f'发现管理员后台路径: {path}',
                                'url': test_url
                            })
                        
                except Exception:
                    continue
            
            # 测试常见的默认凭证
            default_credentials = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('administrator', 'admin'),
                ('root', 'root')
            ]
            
            for username, password in default_credentials:
                try:
                    login_data = {'username': username, 'password': password}
                    response = self.session.post(url, data=login_data, timeout=self.timeout)
                    
                    if response.status_code == 200 and 'dashboard' in response.text.lower():
                        vulnerabilities.append({
                            'type': 'default_credentials',
                            'severity': 'high',
                            'description': f'发现默认凭证: {username}/{password}',
                            'url': url
                        })
                        break
                        
                except Exception:
                    continue
            
        except Exception as e:
            logger.error(f'扫描管理员后台漏洞失败: {str(e)}')
        
        return vulnerabilities
    
    def _scan_captcha_vulnerabilities(self, url: str) -> List[Dict]:
        """扫描验证码漏洞"""
        vulnerabilities = []
        
        try:
            # 测试验证码绕过
            # 1. 测试验证码是否可以重放
            try:
                session1 = requests.Session()
                session2 = requests.Session()
                
                # 获取验证码
                response1 = session1.get(url, timeout=self.timeout)
                response2 = session2.get(url, timeout=self.timeout)
                
                # 尝试使用相同的验证码登录
                login_data = {'username': 'test', 'password': 'test', 'captcha': '1234'}
                
                response1 = session1.post(url, data=login_data, timeout=self.timeout)
                response2 = session2.post(url, data=login_data, timeout=self.timeout)
                
                if response1.status_code == response2.status_code:
                    vulnerabilities.append({
                        'type': 'captcha_reuse',
                        'severity': 'medium',
                        'description': '验证码可能可以重放使用',
                        'url': url
                    })
                    
            except Exception:
                pass
            
            # 2. 测试验证码是否可以绕过
            try:
                # 尝试不提交验证码
                login_data = {'username': 'test', 'password': 'test'}
                response = self.session.post(url, data=login_data, timeout=self.timeout)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'captcha_bypass',
                        'severity': 'medium',
                        'description': '验证码可能可以绕过',
                        'url': url
                    })
                    
            except Exception:
                pass
            
            # 3. 测试验证码识别难度
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if 'captcha' in response.text.lower():
                    vulnerabilities.append({
                        'type': 'captcha_detected',
                        'severity': 'info',
                        'description': '检测到验证码功能',
                        'url': url
                    })
                    
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f'扫描验证码漏洞失败: {str(e)}')
        
        return vulnerabilities
    
    def _scan_general_business_logic(self, url: str) -> List[Dict]:
        """扫描通用业务逻辑漏洞"""
        vulnerabilities = []
        
        try:
            # 测试越权访问
            try:
                # 尝试访问其他用户的数据
                test_urls = [
                    f'{url}/user/1',
                    f'{url}/profile/1',
                    f'{url}/account/1',
                    f'{url}/admin/users/1'
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'id_or',
                                'severity': 'high',
                                'description': f'可能存在越权访问漏洞',
                                'url': test_url
                            })
                            break
                            
                    except Exception:
                        continue
                        
            except Exception:
                pass
            
            # 测试逻辑绕过
            try:
                # 测试负数
                test_data = {'amount': -1, 'quantity': -1, 'price': -1}
                response = self.session.post(url, data=test_data, timeout=self.timeout)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'logic_bypass',
                        'severity': 'medium',
                        'description': '可能存在业务逻辑绕过漏洞（负数）',
                        'url': url
                    })
                    
            except Exception:
                pass
            
            # 测试并发竞争条件
            try:
                # 模拟并发请求
                import threading
                
                results = []
                def make_request():
                    try:
                        response = self.session.get(url, timeout=self.timeout)
                        results.append(response.status_code)
                    except Exception:
                        pass
                
                threads = [threading.Thread(target=make_request) for _ in range(10)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                
                # 检查是否有异常响应
                if len(set(results)) > 1:
                    vulnerabilities.append({
                        'type': 'race_condition',
                        'severity': 'medium',
                        'description': '可能存在并发竞争条件漏洞',
                        'url': url
                    })
                    
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f'扫描通用业务逻辑漏洞失败: {str(e)}')
        
        return vulnerabilities