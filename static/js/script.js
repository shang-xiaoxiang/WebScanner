document.addEventListener('DOMContentLoaded', function() {
    const targetInput = document.getElementById('targetInput');
    const quickScanBtn = document.getElementById('quickScanBtn');
    const fullScanBtn = document.getElementById('fullScanBtn');
    const loading = document.getElementById('loading');
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');

    quickScanBtn.addEventListener('click', function() {
        performScan('quick');
    });

    fullScanBtn.addEventListener('click', function() {
        performScan('full');
    });

    targetInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performScan('quick');
        }
    });

    async function performScan(scanType) {
        const target = targetInput.value.trim();
        
        if (!target) {
            alert('请输入目标域名或IP地址');
            return;
        }

        showLoading();
        hideResults();
        hideError();

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType
                })
            });

            const data = await response.json();

            if (response.ok) {
                displayResults(data);
            } else {
                showError(data.error || '扫描失败');
            }
        } catch (error) {
            showError('网络错误: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    function showLoading() {
        loading.classList.remove('hidden');
    }

    function hideLoading() {
        loading.classList.add('hidden');
    }

    function displayResults(data) {
        document.getElementById('targetInfo').textContent = data.target || '-';
        document.getElementById('ipInfo').textContent = data.ip || '-';
        document.getElementById('urlInfo').textContent = data.url || '-';
        document.getElementById('scanTime').textContent = data.scan_time || '-';

        displayStatusCode(data.status_code || '-');
        displayWAFInfo(data.waf_info || []);
        displayServerInfo(data.server_info || []);
        displayCMSInfo(data.cms_info || []);
        displayPorts(data.open_ports || []);
        displaySensitivePaths(data.sensitive_paths || []);

        resultSection.classList.remove('hidden');
    }

    function displayServerInfo(servers) {
        const container = document.getElementById('serverInfo');
        container.innerHTML = '';

        if (servers.length === 0) {
            container.innerHTML = '<span class="no-data">未识别到服务器类型</span>';
            return;
        }

        servers.forEach(server => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.textContent = server;
            container.appendChild(tag);
        });
    }

    function displayStatusCode(statusCode) {
        const container = document.getElementById('statusCode');
        container.innerHTML = '';

        if (statusCode === '-') {
            container.textContent = statusCode;
            return;
        }

        const statusElement = document.createElement('span');
        statusElement.className = `status-code status-code-${statusCode}`;
        statusElement.textContent = statusCode;
        container.appendChild(statusElement);
    }

    function displayWAFInfo(wafList) {
        const container = document.getElementById('wafInfo');
        container.innerHTML = '';

        if (wafList.length === 0) {
            container.innerHTML = '<span class="no-waf">未检测到WAF</span>';
            return;
        }

        wafList.forEach(waf => {
            const tag = document.createElement('span');
            tag.className = 'waf-tag';
            tag.textContent = waf;
            container.appendChild(tag);
        });
    }

    function displayCMSInfo(cmsList) {
        const container = document.getElementById('cmsInfo');
        container.innerHTML = '';

        if (cmsList.length === 0) {
            container.innerHTML = '<span class="no-data">未识别到CMS框架</span>';
            return;
        }

        cmsList.forEach(cms => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.textContent = cms;
            container.appendChild(tag);
        });
    }

    function displayPorts(ports) {
        const container = document.getElementById('portsInfo');
        container.innerHTML = '';

        if (ports.length === 0) {
            container.innerHTML = '<span class="no-data">未发现开放端口</span>';
            return;
        }

        ports.forEach(port => {
            const portItem = document.createElement('div');
            portItem.className = 'port-item';
            portItem.innerHTML = `
                <div class="port-number">${port.port}</div>
                <div class="port-service">${port.service}</div>
            `;
            container.appendChild(portItem);
        });
    }

    function displaySensitivePaths(paths) {
        const container = document.getElementById('sensitivePaths');
        container.innerHTML = '';

        if (paths.length === 0) {
            container.innerHTML = '<span class="no-data">未发现敏感目录</span>';
            return;
        }

        paths.forEach(path => {
            const pathItem = document.createElement('div');
            pathItem.className = 'path-item';
            
            const statusClass = `status-${path.status}`;
            const statusText = path.status === 'accessible' ? '可访问' : 
                             path.status === 'forbidden' ? '禁止访问' : '重定向';
            
            pathItem.innerHTML = `
                <span class="path-name">${path.path}</span>
                <span class="path-status ${statusClass}">${statusText}</span>
            `;
            container.appendChild(pathItem);
        });
    }

    function showError(message) {
        document.getElementById('errorMessage').textContent = message;
        errorSection.classList.remove('hidden');
    }

    function hideError() {
        errorSection.classList.add('hidden');
    }

    function hideResults() {
        resultSection.classList.add('hidden');
    }

    // 导出 PDF 报告
    document.getElementById('exportPdfBtn').addEventListener('click', async function() {
        const target = targetInput.value.trim();
        if (!target) {
            alert('请先扫描一个目标');
            return;
        }

        try {
            const response = await fetch('/api/export_pdf', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target: target })
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `webscan_report_${target.replace(/\W+/g, '_')}.pdf`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } else {
                const error = await response.json();
                alert('导出失败: ' + error.error);
            }
        } catch (error) {
            alert('网络错误: ' + error.message);
        }
    });
});