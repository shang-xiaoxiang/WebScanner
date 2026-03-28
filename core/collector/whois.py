import whois
from urllib.parse import urlparse

class WhoisCollector:
    def get_info(self, target):
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
