# WebScanner - Web指纹识别与资产探测工具

## 项目简介
WebScanner 是一个基于 Python Flask 的 Web 指纹识别与资产探测工具，可以自动扫描目标域名或 IP 的开放端口、识别服务器类型、CMS 框架以及检测敏感目录。

## 功能特性
- 端口扫描：检测常用端口的开放状态
- 服务器识别：识别 Apache、Nginx、IIS 等服务器类型
- CMS 框架识别：识别 WordPress、Discuz、Dedecms 等常见 CMS
- 敏感目录检测：扫描常见的敏感路径和目录
- 两种扫描模式：快速扫描和完整扫描

## 项目结构
```
WebScanner/
├── app.py                 # Flask 应用主文件
├── requirements.txt       # 项目依赖
├── core/
│   ├── __init__.py
│   ├── fingerprint.py     # 指纹库
│   └── scanner.py         # 扫描器逻辑
├── templates/
│   └── index.html         # 前端页面
└── static/
    ├── css/
    │   └── style.css      # 样式文件
    └── js/
        └── script.js      # JavaScript 脚本
```

## 安装依赖
```bash
pip install -r requirements.txt
```

## 运行项目
```bash
python app.py
```

启动后访问 http://localhost:5000 即可使用。

## 使用说明
1. 在输入框中输入目标域名或 IP 地址
2. 点击"快速扫描"进行基础信息识别
3. 点击"完整扫描"进行全面的端口和目录扫描
4. 查看扫描结果，包括服务器信息、CMS 框架、开放端口和敏感目录

## 注意事项
- 本工具仅供学习和研究使用
- 请勿用于非法用途
- 扫描他人网站前请获得授权