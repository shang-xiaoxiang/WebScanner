"""
WAF自动识别与绕过模块
自动检测目标是否有防火墙并尝试绕过
"""

import requests
import random
from typing import Dict, List, Optional
from core.utils.log_utils import setup_logger

logger = setup_logger('waf_detector')


class WAFDetector:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        
        # 常见的WAF特征
        self.waf_signatures = {
            'cloudflare': [
                'cloudflare',
                'cf-ray',
                '__cfduid',
                'cf_clearance'
            ],
            'aliyun': [
                'aliyun',
                'aliyuncs',
                'aliwaf'
            ],
            'nginx_waf': [
                'nginx',
                'x-waf'
            ],
            'akamai': [
                'akamai',
                'akamai-origin'
            ],
            'imperva': [
                'imperva',
                'incapsula'
            ],
            'aws_waf': [
                'aws',
                'amazon'
            ],
            'f5_waf': [
                'f5',
                'big-ip'
            ],
            'barracuda': [
                'barracuda'
            ],
            'safedog': [
                'safedog',
                'yunsuo'
            ],
            'chaitin': [
                'chaitin',
                'yunsuo'
            ]
        }
        
        # 绕过技术
        self.bypass_techniques = {
            'chunked': self._chunked_encoding,
            'case_mixed': self._case_mixing,
            'encoding': self._special_encoding,
            'random_ua': self._random_user_agent,
            'delay': self._delay_request
        }
    
    def detect(self, url: str) -> Dict:
        """
        检测WAF并尝试绕过
        
        Args:
            url: 目标URL
            
        Returns:
            包含WAF检测和绕过结果的字典
        """
        logger.info(f'开始WAF检测: {url}')
        
        result = {
            'waf_detected': False,
            'waf_type': None,
            'waf_details': {},
            'bypass_methods': [],
            'successful_bypass': None
        }
        
        try:
            # 检测WAF
            waf_info = self._detect_waf(url)
            result.update(waf_info)
            
            if result['waf_detected']:
                logger.info(f'检测到WAF: {result["waf_type"]}')
                
                # 尝试绕过
                bypass_results = self._try_bypass(url, result['waf_type'])
                result['bypass_methods'] = bypass_results
                
                # 找到成功的绕过方法
                for bypass in bypass_results:
                    if bypass['success']:
                        result['successful_bypass'] = bypass['method']
                        break
            else:
                logger.info('未检测到WAF')
            
            logger.info('WAF检测完成')
            return result
            
        except Exception as e:
            logger.error(f'WAF检测失败: {str(e)}')
            return result
    
    def _detect_waf(self, url: str) -> Dict:
        """检测WAF"""
        result = {
            'waf_detected': False,
            'waf_type': None,
            'waf_details': {}
        }
        
        try:
            # 发送测试请求
            response = self.session.get(url, timeout=self.timeout)
            
            # 检查响应头
            headers = dict(response.headers)
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            
            # 检查响应内容
            content = response.text.lower()
            
            # 检查每个WAF特征
            for waf_type, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if signature in content or signature in str(headers_lower):
                        result['waf_detected'] = True
                        result['waf_type'] = waf_type
                        result['waf_details'] = {
                            'signature': signature,
                            'location': 'content' if signature in content else 'header',
                            'status_code': response.status_code
                        }
                        return result
            
            # 检查常见的WAF响应特征
            waf_responses = [
                'access denied',
                'forbidden',
                'blocked',
                'request blocked',
                'security',
                'firewall',
                'waf',
                '防护',
                '拦截',
                '禁止访问'
            ]
            
            for waf_response in waf_responses:
                if waf_response in content:
                    result['waf_detected'] = True
                    result['waf_type'] = 'unknown'
                    result['waf_details'] = {
                        'signature': waf_response,
                        'location': 'content',
                        'status_code': response.status_code
                    }
                    return result
            
            # 检查异常状态码
            if response.status_code in [403, 406, 429, 503]:
                result['waf_detected'] = True
                result['waf_type'] = 'unknown'
                result['waf_details'] = {
                    'signature': f'HTTP {response.status_code}',
                    'location': 'status_code',
                    'status_code': response.status_code
                }
                return result
            
        except Exception as e:
            logger.error(f'检测WAF失败: {str(e)}')
        
        return result
    
    def _try_bypass(self, url: str, waf_type: str) -> List[Dict]:
        """尝试绕过WAF"""
        results = []
        
        # 根据WAF类型选择绕过技术
        bypass_priority = self._get_bypass_priority(waf_type)
        
        for technique in bypass_priority:
            if technique in self.bypass_techniques:
                try:
                    success = self.bypass_techniques[technique](url)
                    results.append({
                        'method': technique,
                        'success': success,
                        'description': self._get_bypass_description(technique)
                    })
                    
                    if success:
                        logger.info(f'绕过成功: {technique}')
                        
                except Exception as e:
                    logger.error(f'绕过失败 {technique}: {str(e)}')
                    results.append({
                        'method': technique,
                        'success': False,
                        'description': self._get_bypass_description(technique),
                        'error': str(e)
                    })
        
        return results
    
    def _get_bypass_priority(self, waf_type: str) -> List[str]:
        """获取绕过技术的优先级"""
        # 根据不同的WAF类型返回不同的绕过策略
        priorities = {
            'cloudflare': ['random_ua', 'delay', 'case_mixed', 'encoding'],
            'aliyun': ['chunked', 'encoding', 'case_mixed', 'random_ua'],
            'nginx_waf': ['chunked', 'case_mixed', 'encoding', 'delay'],
            'unknown': ['random_ua', 'delay', 'case_mixed', 'encoding', 'chunked']
        }
        
        return priorities.get(waf_type, priorities['unknown'])
    
    def _chunked_encoding(self, url: str) -> bool:
        """分块传输编码绕过"""
        try:
            headers = {
                'Transfer-Encoding': 'chunked',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # 将请求分块发送
            payload = 'test=test'
            chunks = [payload[i:i+2] for i in range(0, len(payload), 2)]
            
            for chunk in chunks:
                chunk_data = f"{len(chunk):x}\r\n{chunk}\r\n"
                response = self.session.post(url, data=chunk_data, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f'分块传输绕过失败: {str(e)}')
            return False
    
    def _case_mixing(self, url: str) -> bool:
        """大小写混淆绕过"""
        try:
            # 混合大小写发送请求
            test_params = {
                'Test': 'value',
                'TEST': 'value',
                'TeSt': 'value'
            }
            
            response = self.session.post(url, data=test_params, timeout=self.timeout)
            
            if response.status_code == 200:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f'大小写混淆绕过失败: {str(e)}')
            return False
    
    def _special_encoding(self, url: str) -> bool:
        """特殊字符编码绕过"""
        try:
            # 使用URL编码
            test_params = {
                'test': '%54%45%53%54',  # TEST的URL编码
                'search': '%3Cscript%3Ealert%281%29%3C%2Fscript%3E'  # XSS payload的URL编码
            }
            
            response = self.session.get(url, params=test_params, timeout=self.timeout)
            
            if response.status_code == 200:
                return True
            
            # 使用Unicode编码
            test_params = {
                'test': '\\u0054\\u0045\\u0053\\u0054',  # TEST的Unicode编码
                'search': '\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E'
            }
            
            response = self.session.get(url, params=test_params, timeout=self.timeout)
            
            if response.status_code == 200:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f'特殊编码绕过失败: {str(e)}')
            return False
    
    def _random_user_agent(self, url: str) -> bool:
        """随机User-Agent绕过"""
        try:
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
            ]
            
            for ua in user_agents:
                headers = {'User-Agent': ua}
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f'随机UA绕过失败: {str(e)}')
            return False
    
    def _delay_request(self, url: str) -> bool:
        """延迟请求绕过"""
        try:
            import time
            
            # 发送延迟请求
            for delay in [1, 2, 3, 5]:
                time.sleep(delay)
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f'延迟请求绕过失败: {str(e)}')
            return False
    
    def _get_bypass_description(self, technique: str) -> str:
        """获取绕过技术的描述"""
        descriptions = {
            'chunked': '分块传输编码：将HTTP请求分成多个小块发送',
            'case_mixed': '大小写混淆：混合使用大小写字母绕过规则',
            'encoding': '特殊编码：使用URL编码、Unicode编码等绕过过滤',
            'random_ua': '随机User-Agent：使用不同的浏览器标识绕过检测',
            'delay': '延迟请求：在请求之间添加延迟绕过频率限制'
        }
        
        return descriptions.get(technique, '未知绕过技术')