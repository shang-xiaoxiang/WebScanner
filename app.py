from flask import Flask, render_template, request, jsonify, send_file
from core.scanner import WebScanner
import json
from fpdf import FPDF
import io
import time

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

scanner = WebScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'full')
    
    if not target:
        return jsonify({'error': '请输入目标域名或IP'}), 400
    
    try:
        if scan_type == 'quick':
            result = scanner.quick_scan(target)
        else:
            result = scanner.scan(target)
        
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
    
    pdf.ln(20)
    
    # 页脚
    pdf.set_font('Arial', 'I', 8)
    pdf.cell(0, 10, '报告生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S'), 0, 1, 'C')
    pdf.cell(0, 10, 'WebScanner - Web指纹识别与资产探测工具', 0, 1, 'C')
    
    return pdf

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)