# 全局配置

# 扫描配置
SCAN_TIMEOUT = 5  # 扫描超时时间（秒）
MAX_THREADS = 50  # 最大线程数
SCAN_RATE = 100  # 扫描速率（端口/秒）
DEFAULT_PORT_RANGE = "1-1000"  # 默认端口范围
DEFAULT_SCAN_STRATEGY = "tcp"  # 默认扫描策略

# 指纹配置
FINGERPRINT_CONFIG_PATH = "config/fingerprints/fingerprints.json"
CUSTOM_RULES_DIR = "config/fingerprint/custom"

# 字典配置
DEFAULT_DICTIONARY_PATH = "data/dicts/default.txt"

# 缓存配置
CACHE_DIR = "data/cache"

# 日志配置
LOG_DIR = "logs"
LOG_LEVEL = "INFO"

# Web配置
WEB_HOST = "0.0.0.0"
WEB_PORT = 5001

# 安全配置
MAX_SCAN_PER_IP = 10  # 每IP最大扫描次数
SCAN_INTERVAL = 60  # 扫描间隔（秒）
