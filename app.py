from flask import Flask, render_template, request, jsonify, send_file, Response
from core.scanner import WebScanner
import json
from fpdf import FPDF
import io
import time
import csv

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

scanner = WebScanner()

# 历史记录存储
history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'full')
    port_range = data.get('port_range', '1-1000')
    scan_strategy = data.get('scan_strategy', 'tcp')
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        # 更新扫描器配置
        scanner.port_range = port_range
        scanner.scan_strategy = scan_strategy
        
        if scan_type == 'quick':
            result = scanner.quick_scan(target)
        else:
            result = scanner.scan(target)
        
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
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/quick_scan', methods=['POST'])
def quick_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        result = scanner.quick_scan(target)
        
        # 保存到历史记录
        history.append({
            'target': target,
            'scan_time': result['scan_time'],
            'scan_type': 'quick',
            'result': result
        })
        
        # 限制历史记录数量
        if len(history) > 100:
            history.pop(0)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_pdf', methods=['POST'])
def export_pdf():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        # 执行完整扫描
        result = scanner.scan(target)
        
        # 生成 PDF 报告
        pdf = generate_pdf_report(result)
        
        # 创建字节流
        buffer = io.BytesIO()
        pdf.output(buffer)
        buffer.seek(0)
        
        # 发送文件
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'webscan_report_{target.replace("/", "_")}.pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_pdf_report(result):
    pdf = FPDF()
    pdf.add_page()
    
    # 设置字体
    pdf.set_font('Arial', 'B', 16)
    
    # 标题
    pdf.cell(0, 10, 'WebScanner 扫描报告', 0, 1, 'C')
    pdf.ln(10)
    
    # 基本信息
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '基本信息', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    pdf.cell(40, 8, '目标:', 0, 0)
    pdf.cell(0, 8, result.get('target', '-'), 0, 1)
    
    pdf.cell(40, 8, 'IP地址:', 0, 0)
    pdf.cell(0, 8, result.get('ip', '-'), 0, 1)
    
    pdf.cell(40, 8, 'URL:', 0, 0)
    pdf.cell(0, 8, result.get('url', '-'), 0, 1)
    
    pdf.cell(40, 8, '状态码:', 0, 0)
    pdf.cell(0, 8, str(result.get('status_code', '-')), 0, 1)
    
    pdf.cell(40, 8, '扫描时间:', 0, 0)
    pdf.cell(0, 8, result.get('scan_time', '-'), 0, 1)
    
    pdf.ln(10)
    
    # 服务器信息
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '服务器信息', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    servers = result.get('server_info', [])
    if servers:
        for server in servers:
            pdf.cell(0, 8, f'- {server}', 0, 1)
    else:
        pdf.cell(0, 8, '未识别到服务器类型', 0, 1)
    
    pdf.ln(10)
    
    # CMS 框架
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'CMS 框架', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    cms_list = result.get('cms_info', [])
    if cms_list:
        for cms in cms_list:
            pdf.cell(0, 8, f'- {cms}', 0, 1)
    else:
        pdf.cell(0, 8, '未识别到CMS框架', 0, 1)
    
    pdf.ln(10)
    
    # 安全防护
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '安全防护', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    waf_list = result.get('waf_info', [])
    if waf_list:
        for waf in waf_list:
            pdf.cell(0, 8, f'- {waf}', 0, 1)
    else:
        pdf.cell(0, 8, '未检测到WAF', 0, 1)
    
    pdf.ln(10)
    
    # 编程语言
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '编程语言', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    languages = result.get('programming_languages', [])
    if languages:
        for lang in languages:
            pdf.cell(0, 8, f'- {lang}', 0, 1)
    else:
        pdf.cell(0, 8, '未识别到编程语言', 0, 1)
    
    pdf.ln(10)
    
    # 中间件
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '中间件', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    middleware = result.get('middleware', [])
    if middleware:
        for m in middleware:
            pdf.cell(0, 8, f'- {m}', 0, 1)
    else:
        pdf.cell(0, 8, '未识别到中间件', 0, 1)
    
    pdf.ln(10)
    
    # 开放端口
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '开放端口', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    ports = result.get('open_ports', [])
    if ports:
        for port in ports:
            pdf.cell(40, 8, f'端口 {port["port"]}:', 0, 0)
            pdf.cell(0, 8, port["service"], 0, 1)
    else:
        pdf.cell(0, 8, '未发现开放端口', 0, 1)
    
    pdf.ln(10)
    
    # 敏感目录
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '敏感目录', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    sensitive_paths = result.get('sensitive_paths', [])
    if sensitive_paths:
        for path in sensitive_paths:
            pdf.cell(40, 8, f'路径 {path["path"]}:', 0, 0)
            pdf.cell(0, 8, path["status"], 0, 1)
    else:
        pdf.cell(0, 8, '未发现敏感目录', 0, 1)
    
    pdf.ln(10)
    
    # 子域名
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '子域名', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    subdomains = result.get('subdomains', [])
    if subdomains:
        for subdomain in subdomains:
            pdf.cell(0, 8, f'- {subdomain}', 0, 1)
    else:
        pdf.cell(0, 8, '未发现子域名', 0, 1)
    
    pdf.ln(10)
    
    # CDN 信息
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'CDN 信息', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    cdn_info = result.get('cdn_info', [])
    if cdn_info:
        for cdn in cdn_info:
            pdf.cell(0, 8, f'- {cdn}', 0, 1)
    else:
        pdf.cell(0, 8, '未检测到 CDN', 0, 1)
    
    pdf.ln(10)
    
    # 漏洞信息
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '漏洞信息', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    vulnerabilities = result.get('vulnerabilities', [])
    if vulnerabilities:
        for vuln in vulnerabilities:
            pdf.cell(0, 8, f'- {vuln}', 0, 1)
    else:
        pdf.cell(0, 8, '未检测到漏洞', 0, 1)
    
    pdf.ln(10)
    
    # WHOIS 信息
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'WHOIS 信息', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    
    whois_info = result.get('whois_info', {})
    if whois_info:
        for key, value in whois_info.items():
            if value and value != 'None' and value != '[]':
                pdf.cell(40, 8, f'{key}:', 0, 0)
                pdf.cell(0, 8, str(value), 0, 1)
    else:
        pdf.cell(0, 8, '未获取到 WHOIS 信息', 0, 1)
    
    pdf.ln(20)
    
    # 页脚
    pdf.set_font('Arial', 'I', 8)
    pdf.cell(0, 10, '报告生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S'), 0, 1, 'C')
    pdf.cell(0, 10, 'WebScanner - Web指纹识别与资产探测工具', 0, 1, 'C')
    
    return pdf

@app.route('/api/export_json', methods=['POST'])
def export_json():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        result = scanner.scan(target)
        
        # 创建字节流
        buffer = io.BytesIO()
        buffer.write(json.dumps(result, ensure_ascii=False, indent=2).encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'webscan_report_{target.replace("/", "_")}.json'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_csv', methods=['POST'])
def export_csv():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        result = scanner.scan(target)
        
        # 创建字节流
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        
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
        for cdn in result.get('cdn_info', []):
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
        
        buffer.seek(0)
        
        return Response(
            buffer.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=webscan_report_{target.replace("/", "_")}.csv'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_html', methods=['POST'])
def export_html():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        result = scanner.scan(target)
        
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
                {''.join([f'<li>{cdn}</li>' for cdn in result.get('cdn_info', [])])}
                {'' if result.get('cdn_info', []) else '<li>未检测到 CDN</li>'}
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
        
        return send_file(
            buffer,
            mimetype='text/html',
            as_attachment=True,
            download_name=f'webscan_report_{target.replace("/", "_")}.html'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify(history)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)