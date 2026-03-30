"""
攻击面地图生成模块
自动生成网站攻击面拓扑图
"""

from typing import Dict, List, Optional
from core.utils.log_utils import setup_logger

logger = setup_logger('attack_surface_mapper')


class AttackSurfaceMapper:
    def __init__(self):
        pass
    
    def generate_map(self, scan_result: Dict) -> Dict:
        """
        生成攻击面地图数据
        
        Args:
            scan_result: 扫描结果字典
            
        Returns:
            包含节点和边的字典，用于ECharts关系图
        """
        logger.info('开始生成攻击面地图')
        
        try:
            # 创建节点
            nodes = []
            edges = []
            
            # 主节点（目标）
            target = scan_result.get('target', 'unknown')
            nodes.append({
                'id': 'target',
                'name': target,
                'category': 0,
                'symbolSize': 50,
                'value': 100
            })
            
            # IP节点
            ip = scan_result.get('ip', 'unknown')
            if ip and ip != 'unknown':
                nodes.append({
                    'id': 'ip',
                    'name': f'IP: {ip}',
                    'category': 1,
                    'symbolSize': 40,
                    'value': 80
                })
                edges.append({
                    'source': 'target',
                    'target': 'ip',
                    'name': '解析'
                })
            
            # URL节点
            url = scan_result.get('url', 'unknown')
            if url and url != 'unknown':
                nodes.append({
                    'id': 'url',
                    'name': f'URL: {url}',
                    'category': 2,
                    'symbolSize': 40,
                    'value': 80
                })
                edges.append({
                    'source': 'target',
                    'target': 'url',
                    'name': '访问'
                })
            
            # 端口节点
            ports = scan_result.get('open_ports', [])
            for i, port in enumerate(ports):
                port_id = f'port_{port["port"]}'
                nodes.append({
                    'id': port_id,
                    'name': f'端口 {port["port"]}',
                    'category': 3,
                    'symbolSize': 30,
                    'value': 60,
                    'service': port.get('service', 'unknown')
                })
                edges.append({
                    'source': 'ip',
                    'target': port_id,
                    'name': port.get('service', 'unknown')
                })
            
            # 子域名节点
            subdomains = scan_result.get('subdomains', [])
            for i, subdomain in enumerate(subdomains[:10]):  # 限制显示10个子域名
                subdomain_id = f'subdomain_{i}'
                nodes.append({
                    'id': subdomain_id,
                    'name': subdomain,
                    'category': 4,
                    'symbolSize': 25,
                    'value': 50
                })
                edges.append({
                    'source': 'target',
                    'target': subdomain_id,
                    'name': '子域名'
                })
            
            # 敏感目录节点
            paths = scan_result.get('sensitive_paths', [])
            for i, path in enumerate(paths[:10]):  # 限制显示10个敏感目录
                path_id = f'path_{i}'
                nodes.append({
                    'id': path_id,
                    'name': path.get('path', 'unknown'),
                    'category': 5,
                    'symbolSize': 25,
                    'value': 50,
                    'status': path.get('status', 'unknown')
                })
                edges.append({
                    'source': 'url',
                    'target': path_id,
                    'name': path.get('status', 'unknown')
                })
            
            # 漏洞节点
            vulnerabilities = scan_result.get('vulnerabilities', [])
            for i, vuln in enumerate(vulnerabilities[:10]):  # 限制显示10个漏洞
                vuln_id = f'vuln_{i}'
                nodes.append({
                    'id': vuln_id,
                    'name': f'漏洞: {vuln[:30]}...',  # 截断长文本
                    'category': 6,
                    'symbolSize': 35,
                    'value': 70
                })
                edges.append({
                    'source': 'url',
                    'target': vuln_id,
                    'name': '存在'
                })
            
            # 业务逻辑漏洞节点
            business_logic = scan_result.get('business_logic_vulnerabilities', {})
            for vuln_type, vulns in business_logic.items():
                if vulns:
                    for i, vuln in enumerate(vulns[:3]):  # 每种类型限制显示3个
                        vuln_id = f'business_{vuln_type}_{i}'
                        nodes.append({
                            'id': vuln_id,
                            'name': f'{vuln_type}: {vuln.get("type", "unknown")}',
                            'category': 7,
                            'symbolSize': 30,
                            'value': 65
                        })
                        edges.append({
                            'source': 'url',
                            'target': vuln_id,
                            'name': vuln.get('severity', 'unknown')
                        })
            
            # WAF节点
            waf_info = scan_result.get('waf_info', {})
            if waf_info.get('waf_detected'):
                waf_id = 'waf'
                nodes.append({
                    'id': waf_id,
                    'name': f'WAF: {waf_info.get("waf_type", "unknown")}',
                    'category': 8,
                    'symbolSize': 35,
                    'value': 75
                })
                edges.append({
                    'source': 'target',
                    'target': waf_id,
                    'name': '防护'
                })
            
            # 服务器信息节点
            servers = scan_result.get('server_info', [])
            for i, server in enumerate(servers[:5]):  # 限制显示5个服务器
                server_id = f'server_{i}'
                nodes.append({
                    'id': server_id,
                    'name': server,
                    'category': 9,
                    'symbolSize': 25,
                    'value': 45
                })
                edges.append({
                    'source': 'url',
                    'target': server_id,
                    'name': '服务器'
                })
            
            # CMS节点
            cms_list = scan_result.get('cms_info', [])
            for i, cms in enumerate(cms_list[:3]):  # 限制显示3个CMS
                cms_id = f'cms_{i}'
                nodes.append({
                    'id': cms_id,
                    'name': f'CMS: {cms}',
                    'category': 10,
                    'symbolSize': 30,
                    'value': 55
                })
                edges.append({
                    'source': 'url',
                    'target': cms_id,
                    'name': '框架'
                })
            
            # 编程语言节点
            languages = scan_result.get('programming_languages', [])
            for i, lang in enumerate(languages[:3]):  # 限制显示3个编程语言
                lang_id = f'lang_{i}'
                nodes.append({
                    'id': lang_id,
                    'name': f'语言: {lang}',
                    'category': 11,
                    'symbolSize': 25,
                    'value': 45
                })
                edges.append({
                    'source': 'url',
                    'target': lang_id,
                    'name': '技术栈'
                })
            
            # CDN节点
            cdn_info = scan_result.get('cdn_info', {})
            if isinstance(cdn_info, dict) and cdn_info.get('cdn'):
                cdn_id = 'cdn'
                nodes.append({
                    'id': cdn_id,
                    'name': f'CDN: {cdn_info.get("message", "detected")}',
                    'category': 12,
                    'symbolSize': 30,
                    'value': 55
                })
                edges.append({
                    'source': 'target',
                    'target': cdn_id,
                    'name': '加速'
                })
            elif isinstance(cdn_info, list):
                for i, cdn in enumerate(cdn_info[:3]):  # 限制显示3个CDN
                    cdn_id = f'cdn_{i}'
                    nodes.append({
                        'id': cdn_id,
                        'name': f'CDN: {cdn}',
                        'category': 12,
                        'symbolSize': 30,
                        'value': 55
                    })
                    edges.append({
                        'source': 'target',
                        'target': cdn_id,
                        'name': '加速'
                    })
            
            # 生成类别数据
            categories = [
                {'name': '目标'},
                {'name': 'IP地址'},
                {'name': 'URL'},
                {'name': '端口'},
                {'name': '子域名'},
                {'name': '敏感目录'},
                {'name': '漏洞'},
                {'name': '业务逻辑'},
                {'name': 'WAF'},
                {'name': '服务器'},
                {'name': 'CMS'},
                {'name': '编程语言'},
                {'name': 'CDN'}
            ]
            
            result = {
                'nodes': nodes,
                'edges': edges,
                'categories': categories
            }
            
            logger.info(f'攻击面地图生成完成: {len(nodes)}个节点, {len(edges)}条边')
            return result
            
        except Exception as e:
            logger.error(f'攻击面地图生成失败: {str(e)}')
            return {
                'nodes': [],
                'edges': [],
                'categories': []
            }