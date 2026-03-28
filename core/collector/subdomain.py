import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class SubdomainCollector:
    def __init__(self, max_threads=50):
        self.max_threads = max_threads
    
    def _check_subdomain(self, subdomain):
        """检查子域名是否存在"""
        try:
            # 尝试DNS解析
            answers = dns.resolver.resolve(subdomain, 'A')
            return True
        except Exception:
            try:
                # 回退到socket解析
                socket.gethostbyname(subdomain)
                return True
            except Exception:
                return False
    
    def detect(self, target):
        """子域名探测"""
        subdomains = []
        # 更全面的子域名字典
        common_subdomains = [
            'www', 'api', 'admin', 'test', 'staging', 'dev', 'beta', 'blog', 'mail', 'ftp', 'sftp', 'cdn', 'static', 'images', 'files', 'download', 'upload', 'backup', 'database', 'db', 'mysql', 'postgres', 'redis', 'mongodb', 'elastic', 'search', 'monitor', 'metrics', 'health', 'status', 'docs', 'documentation', 'help', 'support', 'faq', 'about', 'contact', 'feedback', 'news', 'newsletter', 'subscribe', 'unsubscribe', 'rss', 'feed', 'sitemap', 'robots', 'humans', 'crossdomain', 'clientaccesspolicy',
            'app', 'apps', 'auth', 'beta', 'billing', 'build', 'ci', 'code', 'community', 'console', 'dashboard', 'data', 'demo', 'direct', 'dns', 'downloads', 'event', 'events', 'exchange', 'export', 'files', 'forum', 'forums', 'git', 'github', 'help', 'home', 'host', 'hosting', 'import', 'internal', 'intranet', 'jobs', 'lab', 'labs', 'learn', 'library', 'link', 'links', 'live', 'local', 'login', 'logout', 'manage', 'management', 'member', 'members', 'mobile', 'mobil', 'my', 'news', 'notes', 'notification', 'notifications', 'office', 'offline', 'online', 'portal', 'private', 'profile', 'profiles', 'project', 'projects', 'qa', 'register', 'registration', 'report', 'reports', 'reset', 'review', 'reviews', 'sandbox', 'secure', 'security', 'self', 'server', 'servers', 'service', 'services', 'shop', 'shopping', 'site', 'sites', 'smtp', 'sms', 'stage', 'support', 'system', 'systems', 'team', 'teams', 'test', 'testing', 'tools', 'tutorial', 'tutorials', 'user', 'users', 'video', 'videos', 'web', 'website', 'websites', 'wiki', 'work', 'works', 'workspace', 'workspaces'
        ]
        
        # 提取域名
        parsed_url = urlparse(target)
        domain = parsed_url.netloc if parsed_url.netloc else target
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 移除 www 前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # 字典枚举 + DNS 解析验证
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub for sub in common_subdomains}
            
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        subdomain = f"{sub}.{domain}"
                        subdomains.append(subdomain)
                except Exception:
                    pass
        
        return subdomains
