import asyncio
from functools import wraps

def async_retry(max_retries=3, delay=1):
    """异步重试装饰器"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        raise
                    await asyncio.sleep(delay * retries)
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def async_limit_concurrency(max_concurrency):
    """限制异步并发数"""
    semaphore = asyncio.Semaphore(max_concurrency)
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            async with semaphore:
                return await func(*args, **kwargs)
        return wrapper
    return decorator
