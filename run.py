#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
WebScanner 启动脚本
"""

import os
import sys

# 设置PYTHONPATH，确保能够找到core模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入并运行应用（必须使用 socketio.run，否则 WebSocket 与扫描进度不可用）
from web.app import app, socketio

if __name__ == '__main__':
    from config.settings import WEB_HOST, WEB_PORT
    socketio.run(app, debug=True, host=WEB_HOST, port=WEB_PORT, allow_unsafe_werkzeug=True)