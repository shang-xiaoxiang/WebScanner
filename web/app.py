from flask import Flask, render_template, request, jsonify, send_file, Response, make_response
from flask_socketio import SocketIO, emit
from core.scanner.scanner import WebScanner
import json
from fpdf import FPDF
import io
import time
import csv
import os
from core.utils.log_utils import setup_logger

# 设置日志
logger = setup_logger('webapp')

# 设置模板和静态文件路径
app = Flask(__name__, template_folder='templates/templates', static_folder='static/static')
app.config['JSON_AS_ASCII'] = False
app.config['SECRET_KEY'] = 'webscanner-secret-key'

# 初始化 SocketIO（threading 模式以便后台扫描线程能向浏览器推送进度）
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

scanner = WebScanner()


def _emit_socket(event, payload):
    """在后台线程中向所有连接的客户端广播事件。"""
    with app.app_context():
        socketio.emit(event, payload, namespace="/")


def _safe_pdf_text(text):
    """fpdf 1.x 仅支持 Latin-1，避免中文等字符导致导出崩溃。"""
    if text is None:
        return ""
    s = str(text)
    return s.encode("latin-1", errors="replace").decode("latin-1")


def _normalize_cdn_lines(cdn_info):
    """将 scanner 返回的 dict 或 list 统一为可展示的字符串列表。"""
    if not cdn_info:
        return []
    if isinstance(cdn_info, list):
        return [str(x) for x in cdn_info]
    if isinstance(cdn_info, dict):
        lines = []
        if cdn_info.get("cdn"):
            lines.append("CDN: detected")
        msg = cdn_info.get("message")
        if msg:
            lines.append(str(msg))
        ips = cdn_info.get("ips") or []
        if ips:
            lines.append("IPs: " + ", ".join(str(x) for x in ips))
        return lines if lines else ["(no CDN detail)"]
    return [str(cdn_info)]


def get_result_for_export(data):
    """
    优先使用前端传入的扫描结果（避免重复扫描、失败时仍能导出当前页结果）。
    data: { target, result? }
    """
    cached = data.get("result")
    target = (data.get("target") or "").strip()
    if isinstance(cached, dict) and cached.get("target"):
        if not target or cached.get("target", "").strip() == target:
            return cached
    if not target:
        raise ValueError("请输入目标域名或IP，或先完成一次扫描")
    return scanner.scan(target)


def _apply_risk_level(result):
    """根据漏洞与敏感路径粗略给出风险等级，供前端展示。"""
    if not isinstance(result, dict):
        return result
    score = 0
    vulns = result.get("vulnerabilities") or []
    score += min(len(vulns) * 2, 8)
    for p in result.get("sensitive_paths") or []:
        st = (p.get("status") or "").lower()
        if st == "accessible":
            score += 2
        elif st == "forbidden":
            score += 1
    if score >= 6:
        result["risk_level"] = "high"
    elif score >= 2:
        result["risk_level"] = "medium"
    else:
        result["risk_level"] = "low"
    result["risk_score"] = score
    # 前端 v-for 需要列表；scanner 中 cdn 为 dict
    ci = result.get("cdn_info")
    if isinstance(ci, dict):
        result["cdn_info"] = _normalize_cdn_lines(ci)
    return result

# 历史记录存储
history = []

@app.route('/')
def index():
    # 直接返回HTML文件内容，避免Jinja2解析Vue的双大括号
    import os
    file_path = os.path.join(os.path.dirname(__file__), 'templates', 'templates', 'index.html')
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

# WebSocket连接处理
@socketio.on('connect')
def handle_connect(sid):
    logger.info('WebSocket客户端已连接')
    emit('message', {'data': '连接成功'})

@socketio.on('disconnect')
def handle_disconnect(sid):
    logger.info('WebSocket客户端已断开连接')

# 扫描任务管理器
scan_tasks = {}

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'full')
    port_range = data.get('port_range', '1-1000')
    scan_strategy = data.get('scan_strategy', 'tcp')
    
    logger.info(f'收到扫描请求: 目标={target}, 扫描类型={scan_type}, 端口范围={port_range}, 扫描策略={scan_strategy}')
    
    if not target:
        logger.warning('扫描请求缺少目标')
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        # 生成任务ID
        task_id = str(int(time.time()))
        
        # 保存任务信息
        scan_tasks[task_id] = {
            'target': target,
            'status': 'running',
            'start_time': time.time()
        }
        
        # 更新扫描器配置
        scanner.port_scanner.port_range = port_range
        scanner.port_scanner.scan_strategy = scan_strategy
        
        # 启动异步扫描（传入端口与策略，供 full/custom 使用）
        import threading
        thread = threading.Thread(
            target=run_scan,
            args=(task_id, target, scan_type, port_range, scan_strategy),
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'task_id': task_id, 'message': '扫描任务已启动'})
    except Exception as e:
        logger.error(f'扫描失败: 目标={target}, 错误={str(e)}')
        return jsonify({'error': str(e)}), 500

def run_scan(task_id, target, scan_type, port_range, scan_strategy):
    """异步执行扫描任务"""
    try:
        _emit_socket(
            "scan_update",
            {
                "task_id": task_id,
                "status": "running",
                "progress": 2,
                "message": f"开始扫描目标: {target}",
            },
        )

        if scan_type == "quick":
            _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": 15,
                    "message": "快速模式：HTTP 指纹与基础探测...",
                },
            )
            scanner.port_scanner.port_range = port_range
            scanner.port_scanner.scan_strategy = scan_strategy
            result = scanner.quick_scan(target)
        else:
            if scan_type == "full":
                scanner.set_scan_mode("full")
            elif scan_type == "custom":
                scanner.set_scan_mode(
                    "custom",
                    port_range=port_range,
                    scan_strategy=scan_strategy,
                )
            scanner.port_scanner.port_range = port_range
            scanner.port_scanner.scan_strategy = scan_strategy

            _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": 12,
                    "message": "存活检测与 URL 解析...",
                },
            )

            _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": 28,
                    "message": "HTTP 请求与 Web 指纹识别...",
                },
            )

            _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": 45,
                    "message": "子域名 / CDN / 漏洞与 WHOIS...",
                },
            )

            _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": 62,
                    "message": "端口扫描进行中...",
                },
            )

            _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": 78,
                    "message": "敏感目录与深度指纹...",
                },
            )

            result = scanner.scan(target, callback=lambda progress, message: _emit_socket(
                "scan_update",
                {
                    "task_id": task_id,
                    "status": "running",
                    "progress": progress,
                    "message": message,
                },
            ))

        _emit_socket(
            "scan_update",
            {
                "task_id": task_id,
                "status": "running",
                "progress": 85,
                "message": "正在汇总结果...",
            },
        )

        _emit_socket(
            "scan_update",
            {
                "task_id": task_id,
                "status": "running",
                "progress": 92,
                "message": "正在计算风险评级...",
            },
        )

        result = _apply_risk_level(result)

        _emit_socket(
            "scan_update",
            {
                "task_id": task_id,
                "status": "running",
                "progress": 100,
                "message": "扫描完成",
            },
        )

        # 保存到历史记录
        history.append({
            'target': target,
            'scan_time': result['scan_time'],
            'scan_type': scan_type,
            'result': result
        })
        
        # 限制历史记录数量
        if len(history) > 100:
            history.pop(0)
        
        # 发送扫描完成通知
        _emit_socket(
            "scan_complete",
            {
                "task_id": task_id,
                "status": "completed",
                "result": result,
            },
        )
        
        logger.info(f'扫描完成: 目标={target}, 状态=成功')
    except Exception as e:
        error_message = str(e)
        logger.error(f'扫描失败: 目标={target}, 错误={error_message}')
        
        # 发送扫描失败通知
        _emit_socket(
            "scan_error",
            {
                "task_id": task_id,
                "status": "error",
                "error": error_message,
            },
        )
    finally:
        # 从任务列表中移除
        if task_id in scan_tasks:
            del scan_tasks[task_id]

@app.route('/api/quick_scan', methods=['POST'])
def quick_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    logger.info(f'收到快速扫描请求: 目标={target}')
    
    if not target:
        logger.warning('快速扫描请求缺少目标')
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        # 生成任务ID
        task_id = str(int(time.time()))
        
        # 保存任务信息
        scan_tasks[task_id] = {
            'target': target,
            'status': 'running',
            'start_time': time.time()
        }
        
        # 启动异步扫描
        import threading
        thread = threading.Thread(
            target=run_scan,
            args=(task_id, target, 'quick', '1-1000', 'tcp'),
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'task_id': task_id, 'message': '快速扫描任务已启动'})
    except Exception as e:
        logger.error(f'快速扫描失败: 目标={target}, 错误={str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_pdf', methods=['POST'])
def export_pdf():
    data = request.get_json() or {}
    logger.info(f'收到PDF导出请求: target={data.get("target")}')
    try:
        result = get_result_for_export(data)
        target = (result.get("target") or "unknown").replace("/", "_")
        
        # 由于fpdf 1.x不支持中文，我们使用HTML导出作为PDF导出的替代方案
        # 用户可以使用浏览器的打印功能将HTML保存为PDF
        target = (result.get('target') or 'unknown').replace('/', '_')
        cdn_html = ''.join(
            f'<li>{line}</li>' for line in _normalize_cdn_lines(result.get('cdn_info'))
        )
        
        # 生成HTML报告（专门为PDF打印优化）
        html = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WebScanner 扫描报告 - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .info-item {{ margin: 10px 0; }}
                .label {{ font-weight: bold; }}
                @media print {{
                    body {{ margin: 0; }}
                    .no-print {{ display: none; }}
                }}
            </style>
        </head>
        <body>
            <h1>WebScanner 扫描报告</h1>
            
            <h2>基本信息</h2>
            <div class="info-item"><span class="label">目标:</span> {result.get('target', '-')}</div>
            <div class="info-item"><span class="label">IP地址:</span> {result.get('ip', '-')}</div>
            <div class="info-item"><span class="label">URL:</span> {result.get('url', '-')}</div>
            <div class="info-item"><span class="label">状态码:</span> {result.get('status_code', '-')}</div>
            <div class="info-item"><span class="label">扫描时间:</span> {result.get('scan_time', '-')}</div>
            
            <h2>服务器信息</h2>
            <ul>
                {''.join([f'<li>{server}</li>' for server in result.get('server_info', [])])}
                {'' if result.get('server_info', []) else '<li>未识别到服务器类型</li>'}
            </ul>
            
            <h2>CMS 框架</h2>
            <ul>
                {''.join([f'<li>{cms}</li>' for cms in result.get('cms_info', [])])}
                {'' if result.get('cms_info', []) else '<li>未识别到CMS框架</li>'}
            </ul>
            
            <h2>安全防护</h2>
            <ul>
                {''.join([f'<li>{waf}</li>' for waf in result.get('waf_info', [])])}
                {'' if result.get('waf_info', []) else '<li>未检测到WAF</li>'}
            </ul>
            
            <h2>编程语言</h2>
            <ul>
                {''.join([f'<li>{lang}</li>' for lang in result.get('programming_languages', [])])}
                {'' if result.get('programming_languages', []) else '<li>未识别到编程语言</li>'}
            </ul>
            
            <h2>中间件</h2>
            <ul>
                {''.join([f'<li>{middleware}</li>' for middleware in result.get('middleware', [])])}
                {'' if result.get('middleware', []) else '<li>未识别到中间件</li>'}
            </ul>
            
            <h2>开放端口</h2>
            <table>
                <tr><th>端口</th><th>服务</th></tr>
                {''.join([f'<tr><td>{port["port"]}</td><td>{port["service"]}</td></tr>' for port in result.get('open_ports', [])])}
                {'' if result.get('open_ports', []) else '<tr><td colspan="2">未发现开放端口</td></tr>'}
            </table>
            
            <h2>敏感目录</h2>
            <table>
                <tr><th>路径</th><th>状态</th></tr>
                {''.join([f'<tr><td>{path["path"]}</td><td>{path["status"]}</td></tr>' for path in result.get('sensitive_paths', [])])}
                {'' if result.get('sensitive_paths', []) else '<tr><td colspan="2">未发现敏感目录</td></tr>'}
            </table>
            
            <h2>子域名</h2>
            <ul>
                {''.join([f'<li>{subdomain}</li>' for subdomain in result.get('subdomains', [])])}
                {'' if result.get('subdomains', []) else '<li>未发现子域名</li>'}
            </ul>
            
            <h2>CDN 信息</h2>
            <ul>
                {cdn_html if cdn_html else '<li>未检测到 CDN</li>'}
            </ul>
            
            <h2>漏洞信息</h2>
            <ul>
                {''.join([f'<li>{vuln}</li>' for vuln in result.get('vulnerabilities', [])])}
                {'' if result.get('vulnerabilities', []) else '<li>未检测到漏洞</li>'}
            </ul>
            
            <h2>WHOIS 信息</h2>
            <table>
                <tr><th>键</th><th>值</th></tr>
                {''.join([f'<tr><td>{key}</td><td>{value}</td></tr>' for key, value in result.get('whois_info', {}).items() if value and value != 'None' and value != '[]'])}
                {'' if result.get('whois_info', {}) else '<tr><td colspan="2">未获取到 WHOIS 信息</td></tr>'}
            </table>
            
            <div class="no-print" style="margin-top: 20px; padding: 10px; background-color: #f0f0f0; border-left: 4px solid #667eea;">
                <p><strong>提示：</strong>请使用浏览器的打印功能（Ctrl+P）将此页面保存为PDF文件。</p>
            </div>
        </body>
        </html>
        """
        
        buffer = io.BytesIO()
        buffer.write(html.encode('utf-8'))
        buffer.seek(0)
        
        logger.info(f'HTML导出完成（PDF替代方案）: 目标={target}')
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'attachment; filename=webscan_report_{target}.html'
        return response
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f'HTML导出失败: 错误={str(e)}')
        return jsonify({'error': str(e)}), 500


def generate_pdf_report(result):
    t = _safe_pdf_text
    pdf = FPDF()
    pdf.add_page()
    
    # 设置字体
    pdf.set_font('Arial', 'B', 16)
    
    # 标题
    pdf.cell(0, 10, t('WebScanner Scan Report'), 0, 1, 'C')
    pdf.ln(10)
    
    # 基本信息（PDF 使用 Latin-1 安全文本，章节标题用英文避免编码问题）
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Basic info', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    pdf.cell(40, 8, 'Target:', 0, 0)
    pdf.cell(0, 8, t(result.get('target', '-')), 0, 1)
    
    pdf.cell(40, 8, 'IP:', 0, 0)
    pdf.cell(0, 8, t(result.get('ip', '-')), 0, 1)
    
    pdf.cell(40, 8, 'URL:', 0, 0)
    pdf.cell(0, 8, t(result.get('url', '-')), 0, 1)
    
    pdf.cell(40, 8, 'HTTP status:', 0, 0)
    pdf.cell(0, 8, t(str(result.get('status_code', '-'))), 0, 1)
    
    pdf.cell(40, 8, 'Scan time:', 0, 0)
    pdf.cell(0, 8, t(result.get('scan_time', '-')), 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Server', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    servers = result.get('server_info', [])
    if servers:
        for server in servers:
            pdf.cell(0, 8, t(f'- {server}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'CMS', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    cms_list = result.get('cms_info', [])
    if cms_list:
        for cms in cms_list:
            pdf.cell(0, 8, t(f'- {cms}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'WAF', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    waf_list = result.get('waf_info', [])
    if waf_list:
        for waf in waf_list:
            pdf.cell(0, 8, t(f'- {waf}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Languages', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    languages = result.get('programming_languages', [])
    if languages:
        for lang in languages:
            pdf.cell(0, 8, t(f'- {lang}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Middleware', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    middleware = result.get('middleware', [])
    if middleware:
        for m in middleware:
            pdf.cell(0, 8, t(f'- {m}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Open ports', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    ports = result.get('open_ports', [])
    if ports:
        for port in ports:
            pdf.cell(40, 8, t(f'Port {port["port"]}:'), 0, 0)
            pdf.cell(0, 8, t(port.get('service', '')), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Sensitive paths', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    sensitive_paths = result.get('sensitive_paths', [])
    if sensitive_paths:
        for path in sensitive_paths:
            pdf.cell(40, 8, t(f'Path {path["path"]}:'), 0, 0)
            pdf.cell(0, 8, t(str(path.get('status', ''))), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Subdomains', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    subdomains = result.get('subdomains', [])
    if subdomains:
        for subdomain in subdomains:
            pdf.cell(0, 8, t(f'- {subdomain}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'CDN', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    cdn_lines = _normalize_cdn_lines(result.get('cdn_info'))
    if cdn_lines:
        for line in cdn_lines:
            pdf.cell(0, 8, t(f'- {line}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Vulnerabilities', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    vulnerabilities = result.get('vulnerabilities', [])
    if vulnerabilities:
        for vuln in vulnerabilities:
            pdf.cell(0, 8, t(f'- {vuln}'), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(10)
    
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'WHOIS', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    whois_info = result.get('whois_info', {})
    if whois_info:
        for key, value in whois_info.items():
            if value and value != 'None' and value != '[]':
                pdf.cell(40, 8, t(f'{key}:'), 0, 0)
                pdf.cell(0, 8, t(str(value)), 0, 1)
    else:
        pdf.cell(0, 8, '(none)', 0, 1)
    
    pdf.ln(20)
    
    pdf.set_font('Arial', 'I', 8)
    pdf.cell(0, 10, t('Generated: ' + time.strftime('%Y-%m-%d %H:%M:%S')), 0, 1, 'C')
    pdf.cell(0, 10, 'WebScanner', 0, 1, 'C')
    
    return pdf

@app.route('/api/export_json', methods=['POST'])
def export_json():
    data = request.get_json() or {}
    logger.info(f'收到JSON导出请求: target={data.get("target")}')
    try:
        result = get_result_for_export(data)
        target = (result.get('target') or 'unknown').replace('/', '_')
        buffer = io.BytesIO()
        buffer.write(json.dumps(result, ensure_ascii=False, indent=2).encode('utf-8'))
        buffer.seek(0)
        logger.info(f'JSON导出完成: 目标={target}')
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=webscan_report_{target}.json'
        return response
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f'JSON导出失败: 错误={str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_csv', methods=['POST'])
def export_csv():
    data = request.get_json() or {}
    logger.info(f'收到CSV导出请求: target={data.get("target")}')
    try:
        result = get_result_for_export(data)
        target = (result.get('target') or 'unknown').replace('/', '_')
        
        # 创建字节流
        buffer = io.BytesIO()
        # 写入UTF-8 BOM，让Excel正确识别UTF-8编码
        buffer.write('\ufeff'.encode('utf-8'))
        # 使用TextIOWrapper包装BytesIO，以便csv模块使用
        text_buffer = io.TextIOWrapper(buffer, encoding='utf-8', newline='')
        writer = csv.writer(text_buffer)
        
        # 写入基本信息
        writer.writerow(['目标', result.get('target', '-')])
        writer.writerow(['IP地址', result.get('ip', '-')])
        writer.writerow(['URL', result.get('url', '-')])
        writer.writerow(['状态码', result.get('status_code', '-')])
        writer.writerow(['扫描时间', result.get('scan_time', '-')])
        writer.writerow([])
        
        # 写入服务器信息
        writer.writerow(['服务器信息'])
        for server in result.get('server_info', []):
            writer.writerow([server])
        writer.writerow([])
        
        # 写入CMS信息
        writer.writerow(['CMS框架'])
        for cms in result.get('cms_info', []):
            writer.writerow([cms])
        writer.writerow([])
        
        # 写入安全防护
        writer.writerow(['安全防护'])
        for waf in result.get('waf_info', []):
            writer.writerow([waf])
        writer.writerow([])
        
        # 写入编程语言
        writer.writerow(['编程语言'])
        for lang in result.get('programming_languages', []):
            writer.writerow([lang])
        writer.writerow([])
        
        # 写入中间件
        writer.writerow(['中间件'])
        for middleware in result.get('middleware', []):
            writer.writerow([middleware])
        writer.writerow([])
        
        # 写入开放端口
        writer.writerow(['开放端口', '服务'])
        for port in result.get('open_ports', []):
            writer.writerow([port['port'], port['service']])
        writer.writerow([])
        
        # 写入敏感目录
        writer.writerow(['敏感目录', '状态'])
        for path in result.get('sensitive_paths', []):
            writer.writerow([path['path'], path['status']])
        writer.writerow([])
        
        # 写入子域名
        writer.writerow(['子域名'])
        for subdomain in result.get('subdomains', []):
            writer.writerow([subdomain])
        writer.writerow([])
        
        # 写入 CDN 信息
        writer.writerow(['CDN 信息'])
        for cdn in _normalize_cdn_lines(result.get('cdn_info')):
            writer.writerow([cdn])
        writer.writerow([])
        
        # 写入漏洞信息
        writer.writerow(['漏洞信息'])
        for vuln in result.get('vulnerabilities', []):
            writer.writerow([vuln])
        writer.writerow([])
        
        # 写入 WHOIS 信息
        writer.writerow(['WHOIS 信息'])
        for key, value in result.get('whois_info', {}).items():
            if value and value != 'None' and value != '[]':
                writer.writerow([key, value])
        
        # 刷新TextIOWrapper并获取BytesIO的内容
        text_buffer.flush()
        buffer.seek(0)
        
        logger.info(f'CSV导出完成: 目标={target}')
        return Response(
            buffer.getvalue(),
            mimetype='text/csv; charset=utf-8',
            headers={
                'Content-Disposition': f'attachment; filename=webscan_report_{target}.csv'
            },
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f'CSV导出失败: 错误={str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_html', methods=['POST'])
def export_html():
    data = request.get_json() or {}
    logger.info(f'收到HTML导出请求: target={data.get("target")}')
    try:
        result = get_result_for_export(data)
        target = (result.get('target') or 'unknown').replace('/', '_')
        cdn_html = ''.join(
            f'<li>{line}</li>' for line in _normalize_cdn_lines(result.get('cdn_info'))
        )
        
        # 生成HTML报告
        html = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WebScanner 扫描报告 - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .info-item {{ margin: 10px 0; }}
                .label {{ font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>WebScanner 扫描报告</h1>
            
            <h2>基本信息</h2>
            <div class="info-item"><span class="label">目标:</span> {result.get('target', '-')}</div>
            <div class="info-item"><span class="label">IP地址:</span> {result.get('ip', '-')}</div>
            <div class="info-item"><span class="label">URL:</span> {result.get('url', '-')}</div>
            <div class="info-item"><span class="label">状态码:</span> {result.get('status_code', '-')}</div>
            <div class="info-item"><span class="label">扫描时间:</span> {result.get('scan_time', '-')}</div>
            
            <h2>服务器信息</h2>
            <ul>
                {''.join([f'<li>{server}</li>' for server in result.get('server_info', [])])}
                {'' if result.get('server_info', []) else '<li>未识别到服务器类型</li>'}
            </ul>
            
            <h2>CMS 框架</h2>
            <ul>
                {''.join([f'<li>{cms}</li>' for cms in result.get('cms_info', [])])}
                {'' if result.get('cms_info', []) else '<li>未识别到CMS框架</li>'}
            </ul>
            
            <h2>安全防护</h2>
            <ul>
                {''.join([f'<li>{waf}</li>' for waf in result.get('waf_info', [])])}
                {'' if result.get('waf_info', []) else '<li>未检测到WAF</li>'}
            </ul>
            
            <h2>编程语言</h2>
            <ul>
                {''.join([f'<li>{lang}</li>' for lang in result.get('programming_languages', [])])}
                {'' if result.get('programming_languages', []) else '<li>未识别到编程语言</li>'}
            </ul>
            
            <h2>中间件</h2>
            <ul>
                {''.join([f'<li>{middleware}</li>' for middleware in result.get('middleware', [])])}
                {'' if result.get('middleware', []) else '<li>未识别到中间件</li>'}
            </ul>
            
            <h2>开放端口</h2>
            <table>
                <tr><th>端口</th><th>服务</th></tr>
                {''.join([f'<tr><td>{port["port"]}</td><td>{port["service"]}</td></tr>' for port in result.get('open_ports', [])])}
                {'' if result.get('open_ports', []) else '<tr><td colspan="2">未发现开放端口</td></tr>'}
            </table>
            
            <h2>敏感目录</h2>
            <table>
                <tr><th>路径</th><th>状态</th></tr>
                {''.join([f'<tr><td>{path["path"]}</td><td>{path["status"]}</td></tr>' for path in result.get('sensitive_paths', [])])}
                {'' if result.get('sensitive_paths', []) else '<tr><td colspan="2">未发现敏感目录</td></tr>'}
            </table>
            
            <h2>子域名</h2>
            <ul>
                {''.join([f'<li>{subdomain}</li>' for subdomain in result.get('subdomains', [])])}
                {'' if result.get('subdomains', []) else '<li>未发现子域名</li>'}
            </ul>
            
            <h2>CDN 信息</h2>
            <ul>
                {cdn_html if cdn_html else '<li>未检测到 CDN</li>'}
            </ul>
            
            <h2>漏洞信息</h2>
            <ul>
                {''.join([f'<li>{vuln}</li>' for vuln in result.get('vulnerabilities', [])])}
                {'' if result.get('vulnerabilities', []) else '<li>未检测到漏洞</li>'}
            </ul>
            
            <h2>WHOIS 信息</h2>
            <table>
                <tr><th>键</th><th>值</th></tr>
                {''.join([f'<tr><td>{key}</td><td>{value}</td></tr>' for key, value in result.get('whois_info', {}).items() if value and value != 'None' and value != '[]'])}
                {'' if result.get('whois_info', {}) else '<tr><td colspan="2">未获取到 WHOIS 信息</td></tr>'}
            </table>
        </body>
        </html>
        """
        
        buffer = io.BytesIO()
        buffer.write(html.encode('utf-8'))
        buffer.seek(0)
        
        logger.info(f'HTML导出完成: 目标={target}')
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'attachment; filename=webscan_report_{target}.html'
        return response
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f'HTML导出失败: 错误={str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    logger.info('收到历史记录查询请求')
    return jsonify(history)

if __name__ == '__main__':
    from config.settings import WEB_HOST, WEB_PORT
    socketio.run(app, debug=True, host=WEB_HOST, port=WEB_PORT)