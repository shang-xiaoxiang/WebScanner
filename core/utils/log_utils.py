import logging
import os
import time
from logging.handlers import TimedRotatingFileHandler

class WindowsTimedRotatingFileHandler(TimedRotatingFileHandler):
    """解决Windows下日志文件被占用无法重命名的问题"""
    def __init__(self, filename, when='h', interval=1, backupCount=0, encoding=None, delay=False, utc=False, atTime=None):
        super().__init__(filename, when, interval, backupCount, encoding, delay, utc, atTime)
    
    def doRollover(self):
        """重写doRollover方法，解决Windows文件锁定问题"""
        if self.stream:
            self.stream.close()
            self.stream = None
        
        # 计算新的文件名
        currentTime = int(time.time())
        dstNow = time.localtime(currentTime)[-1]
        t = self.computeRollover(currentTime)
        if self.utc:
            timeTuple = time.gmtime(t)
        else:
            timeTuple = time.localtime(t)
            dstThen = timeTuple[-1]
            if dstNow != dstThen:
                if dstNow:
                    addend = 3600
                else:
                    addend = -3600
                timeTuple = time.localtime(t + addend)
        
        dfn = self.rotation_filename(self.baseFilename + "." + time.strftime(self.suffix, timeTuple))
        
        # 尝试重命名文件，如果失败则等待一段时间后重试
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                if os.path.exists(dfn):
                    os.remove(dfn)
                if os.path.exists(self.baseFilename):
                    os.rename(self.baseFilename, dfn)
                break
            except PermissionError:
                if attempt < max_attempts - 1:
                    time.sleep(0.1)
                else:
                    # 如果多次尝试后仍失败，放弃重命名
                    pass
        
        # 重新打开日志文件
        if not self.delay:
            self.stream = self._open()

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
        file_handler = WindowsTimedRotatingFileHandler(
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
