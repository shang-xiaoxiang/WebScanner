import logging
import os
from logging.handlers import TimedRotatingFileHandler

def setup_logger(name, log_dir='logs', level=logging.INFO):
    """设置日志记录器
    
    Args:
        name: 日志记录器名称
        log_dir: 日志目录
        level: 日志级别
    
    Returns:
        logging.Logger: 配置好的日志记录器
    """
    # 确保日志目录存在
    os.makedirs(log_dir, exist_ok=True)
    
    # 创建日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 避免重复添加处理器
    if not logger.handlers:
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        
        # 创建文件处理器（按日期分割）
        file_handler = TimedRotatingFileHandler(
            os.path.join(log_dir, f'{name}.log'),
            when='midnight',
            interval=1,
            backupCount=30
        )
        file_handler.setLevel(level)
        
        # 配置日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        # 添加处理器
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
    
    return logger

# 创建默认日志记录器
default_logger = setup_logger('webscanner')
