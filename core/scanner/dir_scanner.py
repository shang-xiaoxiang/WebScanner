import requests
import hashlib
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# 尝试导入异步库
try:
    import asyncio
    import aiohttp
    HAS_ASYNC = True
except ImportError:
    HAS_ASYNC = False

class DirScanner:
    def __init__(self, timeout=5, max_threads=50, concurrency=20):
        self.timeout = timeout
        self.max_threads = max_threads
        self.concurrency = concurrency
        self.custom_dictionary = []
        self.dictionary_level = 'basic'  # basic, high, full
        self.ignore_redirects = False
        self.random_scan = False
        self.hash_404 = None
    
    def set_custom_dictionary(self, dictionary):
        """设置自定义敏感目录字典"""
        if isinstance(dictionary, list):
            self.custom_dictionary = dictionary
    
    def set_dictionary_level(self, level):
        """设置字典级别"""
        if level in ['basic', 'high', 'full']:
            self.dictionary_level = level
    
    def set_ignore_redirects(self, ignore):
        """设置是否忽略重定向"""
        self.ignore_redirects = ignore
    
    def set_random_scan(self, random_scan):
        """设置是否随机扫描"""
        self.random_scan = random_scan
    
    def load_dictionary_from_file(self, file_path):
        """从文件加载敏感目录字典"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                paths = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            self.custom_dictionary = paths
            return True
        except Exception:
            return False
    
    def _get_dictionary(self):
        """获取字典"""
        if self.custom_dictionary:
            return self.custom_dictionary
        
        # 基础版字典
        basic_dict = [
            '/admin/', '/admin/login.php', '/admin/index.php', '/admin/dashboard.php',
            '/config.php', '/configuration.php', '/settings.php',
            '/wp-admin/', '/wp-login.php', '/wp-config.php',
            '/joomla/administrator/', '/administrator/',
            '/drupal/admin/', '/administer/',
            '/phpmyadmin/', '/mysql/', '/adminer/',
            '/backup/', '/backups/', '/dump/',
            '/.env', '/.env.local', '/.env.production',
            '/robots.txt', '/sitemap.xml',
            '/api/', '/api/v1/', '/api/v2/',
            '/test/', '/tests/', '/dev/',
            '/upload/', '/uploads/', '/images/',
            '/download/', '/downloads/',
            '/doc/', '/docs/', '/documentation/',
            '/readme.md', '/README.md', '/readme.txt',
            '/license.txt', '/LICENSE.txt',
            '/CHANGELOG.md', '/changelog.txt'
        ]
        
        # 高危版字典
        high_dict = basic_dict + [
            '/backup.sql', '/backup.bak', '/backup.rar', '/backup.zip',
            '/database.sql', '/db.sql', '/dump.sql',
            '/wordpress.sql', '/joomla.sql',
            '/.htaccess', '/.htpasswd',
            '/web.config', '/web.config.bak',
            '/phpinfo.php', '/info.php', '/php_info.php',
            '/debug.php', '/test.php', '/test1.php',
            '/shell.php', '/webshell.php', '/backdoor.php',
            '/cmd.php', '/command.php', '/exec.php',
            '/upload.php', '/fileupload.php', '/uploader.php',
            '/adminer.php', '/phpmyadmin.php', '/mysql.php',
            '/config.bak', '/settings.bak', '/configuration.bak',
            '/.git/', '/.svn/', '/.hg/',
            '/composer.json', '/package.json', '/requirements.txt',
            '/.env.example', '/.env.sample',
            '/server-status', '/status',
            '/cgi-bin/', '/cgi/',
            '/logs/', '/log/',
            '/tmp/', '/temp/',
            '/session/', '/sessions/'
        ]
        
        # 全量版字典
        full_dict = high_dict + [
            '/index.html', '/index.htm', '/index.php', '/index.asp', '/index.aspx',
            '/default.html', '/default.htm', '/default.php', '/default.asp', '/default.aspx',
            '/home.html', '/home.htm', '/home.php',
            '/about.html', '/about.htm', '/about.php',
            '/contact.html', '/contact.htm', '/contact.php',
            '/login.html', '/login.htm', '/login.php',
            '/register.html', '/register.htm', '/register.php',
            '/profile.html', '/profile.htm', '/profile.php',
            '/dashboard.html', '/dashboard.htm', '/dashboard.php',
            '/admin.html', '/admin.htm', '/admin.php',
            '/user.html', '/user.htm', '/user.php',
            '/users.html', '/users.htm', '/users.php',
            '/product.html', '/product.htm', '/product.php',
            '/products.html', '/products.htm', '/products.php',
            '/order.html', '/order.htm', '/order.php',
            '/orders.html', '/orders.htm', '/orders.php',
            '/cart.html', '/cart.htm', '/cart.php',
            '/checkout.html', '/checkout.htm', '/checkout.php',
            '/payment.html', '/payment.htm', '/payment.php',
            '/shipping.html', '/shipping.htm', '/shipping.php',
            '/tracking.html', '/tracking.htm', '/tracking.php',
            '/search.html', '/search.htm', '/search.php',
            '/results.html', '/results.htm', '/results.php',
            '/category.html', '/category.htm', '/category.php',
            '/categories.html', '/categories.htm', '/categories.php',
            '/tag.html', '/tag.htm', '/tag.php',
            '/tags.html', '/tags.htm', '/tags.php',
            '/blog.html', '/blog.htm', '/blog.php',
            '/post.html', '/post.htm', '/post.php',
            '/posts.html', '/posts.htm', '/posts.php',
            '/article.html', '/article.htm', '/article.php',
            '/articles.html', '/articles.htm', '/articles.php',
            '/news.html', '/news.htm', '/news.php',
            '/event.html', '/event.htm', '/event.php',
            '/events.html', '/events.htm', '/events.php',
            '/gallery.html', '/gallery.htm', '/gallery.php',
            '/photo.html', '/photo.htm', '/photo.php',
            '/photos.html', '/photos.htm', '/photos.php',
            '/video.html', '/video.htm', '/video.php',
            '/videos.html', '/videos.htm', '/videos.php',
            '/audio.html', '/audio.htm', '/audio.php',
            '/audios.html', '/audios.htm', '/audios.php',
            '/file.html', '/file.htm', '/file.php',
            '/files.html', '/files.htm', '/files.php',
            '/download.html', '/download.htm', '/download.php',
            '/downloads.html', '/downloads.htm', '/downloads.php',
            '/upload.html', '/upload.htm', '/upload.php',
            '/uploads.html', '/uploads.htm', '/uploads.php',
            '/image.html', '/image.htm', '/image.php',
            '/images.html', '/images.htm', '/images.php',
            '/document.html', '/document.htm', '/document.php',
            '/documents.html', '/documents.htm', '/documents.php',
            '/pdf.html', '/pdf.htm', '/pdf.php',
            '/pdfs.html', '/pdfs.htm', '/pdfs.php',
            '/excel.html', '/excel.htm', '/excel.php',
            '/excels.html', '/excels.htm', '/excels.php',
            '/word.html', '/word.htm', '/word.php',
            '/words.html', '/words.htm', '/words.php',
            '/powerpoint.html', '/powerpoint.htm', '/powerpoint.php',
            '/powerpoints.html', '/powerpoints.htm', '/powerpoints.php',
            '/zip.html', '/zip.htm', '/zip.php',
            '/zips.html', '/zips.htm', '/zips.php',
            '/rar.html', '/rar.htm', '/rar.php',
            '/rars.html', '/rars.htm', '/rars.php',
            '/7z.html', '/7z.htm', '/7z.php',
            '/7zs.html', '/7zs.htm', '/7zs.php'
        ]
        
        if self.dictionary_level == 'basic':
            return basic_dict
        elif self.dictionary_level == 'high':
            return high_dict
        else:
            return full_dict
    
    def _calculate_content_hash(self, content):
        """计算内容的MD5哈希值"""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _detect_404_page(self, base_url):
        """检测404页面"""
        try:
            # 请求一个不存在的路径
            url = base_url.rstrip('/') + '/this-path-does-not-exist-1234567890'
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 404:
                self.hash_404 = self._calculate_content_hash(response.text)
        except Exception:
            pass
    
    async def _async_scan_sensitive_paths(self, base_url, sensitive_paths):
        """异步扫描敏感目录"""
        found_paths = []
        
        # 控制并发数
        semaphore = asyncio.Semaphore(self.concurrency)
        
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
        """异步检查路径"""
        try:
            url = base_url.rstrip('/') + path
            async with session.get(url, timeout=self.timeout, allow_redirects=False) as response:
                # 检查状态码
                status_code = response.status
                
                # 检查响应内容，判断是否为 404 统一页面
                content = await response.text()
                
                # 智能过滤：排除 404 统一页面
                if status_code == 404:
                    content_hash = self._calculate_content_hash(content)
                    if content_hash == self.hash_404:
                        return None
                
                # 过滤重定向
                if self.ignore_redirects and (status_code == 301 or status_code == 302):
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
    
    def _check_path(self, base_url, path):
        """同步检查路径"""
        try:
            url = base_url.rstrip('/') + path
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            
            # 检查状态码
            status_code = response.status_code
            
            # 检查响应内容，判断是否为 404 统一页面
            content = response.text
            
            # 智能过滤：排除 404 统一页面
            if status_code == 404:
                content_hash = self._calculate_content_hash(content)
                if content_hash == self.hash_404:
                    return None
            
            # 过滤重定向
            if self.ignore_redirects and (status_code == 301 or status_code == 302):
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
    
    def scan(self, base_url, sensitive_paths=None):
        """扫描敏感目录"""
        # 检测404页面
        self._detect_404_page(base_url)
        
        # 使用自定义字典或默认字典
        if self.custom_dictionary:
            paths_to_scan = self.custom_dictionary
        elif sensitive_paths:
            paths_to_scan = sensitive_paths
        else:
            paths_to_scan = self._get_dictionary()
        
        # 随机扫描
        if self.random_scan:
            random.shuffle(paths_to_scan)
        
        if HAS_ASYNC:
            try:
                # 使用异步扫描提高效率
                return asyncio.run(self._async_scan_sensitive_paths(base_url, paths_to_scan))
            except Exception:
                # 异步扫描失败时回退到同步扫描
                pass
        
        # 使用同步扫描
        found_paths = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_path, base_url, path): path for path in paths_to_scan}
            
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
