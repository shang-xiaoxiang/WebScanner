"""
AI渗透测试报告生成模块
支持多种AI模型，自动生成完整的渗透测试报告
"""

import requests
import json
from typing import Dict, List, Optional
from core.utils.log_utils import setup_logger

logger = setup_logger('ai_report_generator')


class AIReportGenerator:
    def __init__(self, api_key: str = None, model: str = "gpt-3.5-turbo"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.openai.com/v1/chat/completions"
    
    def generate_report(self, scan_result: Dict) -> Dict:
        """
        生成AI渗透测试报告
        
        Args:
            scan_result: 扫描结果字典
            
        Returns:
            包含AI生成的报告、风险等级、修复建议的字典
        """
        try:
            prompt = self._build_prompt(scan_result)
            ai_response = self._call_ai_model(prompt)
            
            report = {
                'ai_report': ai_response.get('report', ''),
                'risk_level': ai_response.get('risk_level', 'unknown'),
                'fix_suggestions': ai_response.get('fix_suggestions', []),
                'vulnerability_details': ai_response.get('vulnerability_details', []),
                'security_score': ai_response.get('security_score', 50)
            }
            
            logger.info('AI报告生成成功')
            return report
            
        except Exception as e:
            logger.error(f'AI报告生成失败: {str(e)}')
            return self._generate_fallback_report(scan_result)
    
    def _build_prompt(self, scan_result: Dict) -> str:
        """构建AI提示词"""
        prompt = f"""
请基于以下网站扫描结果，生成一份专业的渗透测试报告。

扫描目标: {scan_result.get('target', 'unknown')}
IP地址: {scan_result.get('ip', 'unknown')}
URL: {scan_result.get('url', 'unknown')}
状态码: {scan_result.get('status_code', 'unknown')}

开放端口: {', '.join([f"{p['port']}({p['service']})" for p in scan_result.get('open_ports', [])])}

服务器信息: {', '.join(scan_result.get('server_info', []))}
CMS框架: {', '.join(scan_result.get('cms_info', []))}
编程语言: {', '.join(scan_result.get('programming_languages', []))}
中间件: {', '.join(scan_result.get('middleware', []))}

敏感目录: {len(scan_result.get('sensitive_paths', []))}个
子域名: {len(scan_result.get('subdomains', []))}个
漏洞: {', '.join(scan_result.get('vulnerabilities', []))}

请以JSON格式返回以下内容：
{{
    "report": "完整的渗透测试报告，包括概述、发现的问题、风险评估等",
    "risk_level": "风险等级（high/medium/low/info）",
    "fix_suggestions": ["修复建议1", "修复建议2", ...],
    "vulnerability_details": ["漏洞详情1", "漏洞详情2", ...],
    "security_score": 0-100的安全评分
}}

报告要求：
1. 专业、详细、有针对性
2. 提供具体的修复建议
3. 对每个漏洞进行详细分析
4. 给出整体安全评分
5. 用中文编写
"""
        return prompt
    
    def _call_ai_model(self, prompt: str) -> Dict:
        """调用AI模型"""
        try:
            if not self.api_key:
                logger.warning('未配置API密钥，使用模拟AI响应')
                return self._generate_mock_ai_response()
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            data = {
                'model': self.model,
                'messages': [
                    {'role': 'system', 'content': '你是一个专业的网络安全专家，擅长渗透测试和安全评估。'},
                    {'role': 'user', 'content': prompt}
                ],
                'temperature': 0.7,
                'max_tokens': 2000
            }
            
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            content = result['choices'][0]['message']['content']
            
            # 尝试解析JSON响应
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                logger.warning('AI响应不是有效的JSON，使用模拟响应')
                return self._generate_mock_ai_response()
                
        except Exception as e:
            logger.error(f'调用AI模型失败: {str(e)}')
            return self._generate_mock_ai_response()
    
    def _generate_mock_ai_response(self) -> Dict:
        """生成模拟AI响应"""
        return {
            'report': """
# 渗透测试报告

## 1. 执行概述
本次渗透测试针对目标系统进行了全面的安全评估，包括端口扫描、服务识别、漏洞检测等多个方面。

## 2. 发现的安全问题
- 开放端口过多，增加了攻击面
- 存在敏感目录泄露风险
- 部分服务版本较旧，存在已知漏洞
- 未检测到有效的安全防护措施

## 3. 风险评估
基于扫描结果，目标系统存在中等安全风险，建议及时修复发现的问题。

## 4. 总体建议
1. 关闭不必要的端口和服务
2. 更新所有软件到最新版本
3. 配置适当的访问控制
4. 定期进行安全审计
""",
            'risk_level': 'medium',
            'fix_suggestions': [
                '关闭不必要的端口，仅保留必需的服务端口',
                '更新所有软件和中间件到最新版本',
                '配置Web应用防火墙（WAF）',
                '实施强密码策略和多因素认证',
                '定期进行安全扫描和渗透测试',
                '限制敏感目录的访问权限'
            ],
            'vulnerability_details': [
                '端口扫描发现多个开放端口，可能被攻击者利用',
                '敏感目录可能泄露系统信息',
                '部分服务存在已知漏洞风险',
                '缺乏有效的安全防护机制'
            ],
            'security_score': 65
        }
    
    def _generate_fallback_report(self, scan_result: Dict) -> Dict:
        """生成备用报告（当AI服务不可用时）"""
        vulnerabilities = scan_result.get('vulnerabilities', [])
        open_ports = scan_result.get('open_ports', [])
        sensitive_paths = scan_result.get('sensitive_paths', [])
        
        # 简单的风险评估
        risk_level = 'info'
        if vulnerabilities:
            risk_level = 'high'
        elif len(open_ports) > 10 or len(sensitive_paths) > 5:
            risk_level = 'medium'
        elif open_ports or sensitive_paths:
            risk_level = 'low'
        
        # 计算安全评分
        security_score = 100
        security_score -= len(vulnerabilities) * 15
        security_score -= len(open_ports) * 2
        security_score -= len(sensitive_paths) * 3
        security_score = max(0, min(100, security_score))
        
        return {
            'ai_report': f"""
# 自动生成的渗透测试报告

## 目标信息
- 目标: {scan_result.get('target', 'unknown')}
- IP: {scan_result.get('ip', 'unknown')}
- URL: {scan_result.get('url', 'unknown')}

## 扫描结果摘要
- 开放端口: {len(open_ports)}个
- 敏感目录: {len(sensitive_paths)}个
- 检测到的漏洞: {len(vulnerabilities)}个

## 风险评估
当前风险等级: {risk_level}
安全评分: {security_score}/100

## 发现的问题
{chr(10).join([f"- {vuln}" for vuln in vulnerabilities]) if vulnerabilities else "- 未发现明显漏洞"}

## 建议
1. 定期更新系统和软件
2. 关闭不必要的端口
3. 配置适当的访问控制
4. 实施安全监控和日志审计
""",
            'risk_level': risk_level,
            'fix_suggestions': [
                '关闭不必要的端口和服务',
                '更新所有软件到最新版本',
                '配置Web应用防火墙',
                '实施强密码策略',
                '定期进行安全扫描'
            ],
            'vulnerability_details': vulnerabilities,
            'security_score': security_score
        }