document.addEventListener('DOMContentLoaded', function() {
    const targetInput = document.getElementById('targetInput');
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.querySelector('.progress-fill');
    const progressText = document.querySelector('.progress-text');
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');
    const historySection = document.getElementById('historySection');
    const historyContent = document.getElementById('historyContent');
    
    // 标签页切换
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tab = this.getAttribute('data-tab');
            
            // 更新标签按钮状态
            tabBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // 更新标签内容
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tab + 'Section') {
                    content.classList.add('active');
                    
                    // 如果切换到历史记录标签，加载历史记录
                    if (tab === 'history') {
                        loadHistory();
                    }
                }
            });
        });
    });

    // 开始扫描
    startScanBtn.addEventListener('click', function() {
        performScan();
    });

    // 停止扫描
    stopScanBtn.addEventListener('click', function() {
        if (window.scanAbortController) {
            window.scanAbortController.abort();
            this.textContent = '已中止';
            this.disabled = true;
        }
    });

    // 回车键触发扫描
    targetInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performScan();
        }
    });

    async function performScan() {
        const target = targetInput.value.trim();
        const scanType = document.querySelector('input[name="scanType"]:checked').value;
        const portRange = document.getElementById('portRange').value;
        const scanStrategy = document.getElementById('scanStrategy').value;
        
        if (!target) {
            alert('请输入目标域名或IP地址');
            return;
        }

        showProgress();
        updateProgress(0, '准备中...');
        hideResults();
        hideError();
        
        // 显示停止按钮
        stopScanBtn.classList.remove('hidden');
        stopScanBtn.textContent = '停止扫描';
        stopScanBtn.disabled = false;

        try {
            // 创建中止控制器
            window.scanAbortController = new AbortController();
            
            // 模拟进度更新
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += 10;
                if (progress <= 90) {
                    updateProgress(progress, '扫描中...');
                }
            }, 500);
            
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType,
                    port_range: portRange,
                    scan_strategy: scanStrategy
                }),
                signal: window.scanAbortController.signal
            });

            clearInterval(progressInterval);
            updateProgress(100, '扫描完成');

            const data = await response.json();

            if (response.ok) {
                displayResults(data);
            } else {
                showError(data.error || '扫描失败');
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                showError('扫描已中止');
            } else {
                showError('网络错误: ' + error.message);
            }
        } finally {
            setTimeout(() => {
                hideProgress();
                stopScanBtn.classList.add('hidden');
            }, 1000);
        }
    }

    function showProgress() {
        progressContainer.classList.remove('hidden');
    }

    function hideProgress() {
        progressContainer.classList.add('hidden');
    }

    function updateProgress(percent, text) {
        progressFill.style.width = `${percent}%`;
        progressText.textContent = text;
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
        displayLanguageInfo(data.programming_languages || []);
        displayMiddlewareInfo(data.middleware || []);
        displayPorts(data.open_ports || []);
        displaySensitivePaths(data.sensitive_paths || []);
        displaySubdomains(data.subdomains || []);
        displayCDNInfo(data.cdn_info || []);
        displayVulnerabilities(data.vulnerabilities || []);
        displayWHOISInfo(data.whois_info || {});

        // 显示结果标签页
        document.querySelector('[data-tab="result"]').click();
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

    function displayLanguageInfo(languages) {
        const container = document.getElementById('languageInfo');
        container.innerHTML = '';

        if (languages.length === 0) {
            container.innerHTML = '<span class="no-data">未识别到编程语言</span>';
            return;
        }

        languages.forEach(lang => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.textContent = lang;
            container.appendChild(tag);
        });
    }

    function displayMiddlewareInfo(middleware) {
        const container = document.getElementById('middlewareInfo');
        container.innerHTML = '';

        if (middleware.length === 0) {
            container.innerHTML = '<span class="no-data">未识别到中间件</span>';
            return;
        }

        middleware.forEach(m => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.textContent = m;
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
            
            // 隐藏图表
            const portChart = document.getElementById('portChart');
            if (portChart) {
                portChart.style.display = 'none';
            }
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

        // 绘制端口分布图
        drawPortChart(ports);
    }

    function drawPortChart(ports) {
        const ctx = document.getElementById('portChart').getContext('2d');
        
        // 统计服务类型
        const serviceCounts = {};
        ports.forEach(port => {
            const service = port.service || 'Unknown';
            serviceCounts[service] = (serviceCounts[service] || 0) + 1;
        });
        
        // 销毁旧图表
        if (window.portChart && typeof window.portChart.destroy === 'function') {
            window.portChart.destroy();
        }
        
        // 创建新图表
        window.portChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: Object.keys(serviceCounts),
                datasets: [{
                    data: Object.values(serviceCounts),
                    backgroundColor: [
                        'rgba(102, 126, 234, 0.8)',
                        'rgba(118, 75, 162, 0.8)',
                        'rgba(40, 167, 69, 0.8)',
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(23, 162, 184, 0.8)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                    },
                    title: {
                        display: true,
                        text: '端口服务分布'
                    }
                }
            }
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
            
            let statusClass = `status-${path.status}`;
            let statusText = '';
            let riskClass = '';
            
            switch (path.status) {
                case 'accessible':
                    statusText = '可访问';
                    riskClass = 'risk-high';
                    break;
                case 'forbidden':
                    statusText = '禁止访问';
                    riskClass = 'risk-medium';
                    break;
                case 'redirect':
                    statusText = '重定向';
                    riskClass = 'risk-low';
                    break;
                default:
                    statusText = path.status;
                    riskClass = 'risk-low';
            }
            
            pathItem.innerHTML = `
                <span class="path-name">${path.path}</span>
                <span class="path-status ${statusClass} ${riskClass}">${statusText}</span>
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

    // 加载历史记录
    async function loadHistory() {
        try {
            const response = await fetch('/api/history');
            const data = await response.json();
            
            if (data.length === 0) {
                historyContent.innerHTML = '<div class="no-data">暂无历史记录</div>';
                return;
            }
            
            let html = `
                <table class="history-table">
                    <thead>
                        <tr>
                            <th>目标</th>
                            <th>扫描时间</th>
                            <th>扫描类型</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            data.forEach(item => {
                html += `
                    <tr>
                        <td>${item.target}</td>
                        <td>${item.scan_time}</td>
                        <td>${item.scan_type === 'full' ? '全面扫描' : '快速扫描'}</td>
                        <td>
                            <button class="view-btn" onclick="viewHistoryResult(${JSON.stringify(item.result).replace(/"/g, '&quot;')})")">查看结果</button>
                        </td>
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
            `;
            
            historyContent.innerHTML = html;
        } catch (error) {
            historyContent.innerHTML = '<div class="error-message">加载历史记录失败: ' + error.message + '</div>';
        }
    }

    // 查看历史记录结果
    window.viewHistoryResult = function(result) {
        displayResults(result);
    };

    // 导出报告
    function exportReport(format) {
        const target = targetInput.value.trim();
        if (!target) {
            alert('请先扫描一个目标');
            return;
        }

        fetch(`/api/export_${format}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        })
        .then(response => {
            if (response.ok) {
                return response.blob();
            } else {
                return response.json().then(error => {
                    throw new Error(error.error);
                });
            }
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `webscan_report_${target.replace(/\W+/g, '_')}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        })
        .catch(error => {
            alert('导出失败: ' + error.message);
        });
    }

    // 导出 PDF 报告
    document.getElementById('exportPdfBtn').addEventListener('click', function() {
        exportReport('pdf');
    });

    // 导出 JSON 报告
    document.getElementById('exportJsonBtn').addEventListener('click', function() {
        exportReport('json');
    });

    // 导出 CSV 报告
    document.getElementById('exportCsvBtn').addEventListener('click', function() {
        exportReport('csv');
    });

    // 导出 HTML 报告
    document.getElementById('exportHtmlBtn').addEventListener('click', function() {
        exportReport('html');
    });

    // 显示子域名
    function displaySubdomains(subdomains) {
        const container = document.getElementById('subdomainsInfo');
        container.innerHTML = '';

        if (subdomains.length === 0) {
            container.innerHTML = '<span class="no-data">未发现子域名</span>';
            return;
        }

        subdomains.forEach(subdomain => {
            const subdomainItem = document.createElement('div');
            subdomainItem.className = 'subdomain-item';
            subdomainItem.textContent = subdomain;
            container.appendChild(subdomainItem);
        });
    }

    // 显示 CDN 信息
    function displayCDNInfo(cdnList) {
        const container = document.getElementById('cdnInfo');
        container.innerHTML = '';

        if (cdnList.length === 0) {
            container.innerHTML = '<span class="no-data">未检测到 CDN</span>';
            return;
        }

        cdnList.forEach(cdn => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.textContent = cdn;
            container.appendChild(tag);
        });
    }

    // 显示漏洞信息
    function displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerabilitiesInfo');
        container.innerHTML = '';

        if (vulnerabilities.length === 0) {
            container.innerHTML = '<span class="no-data">未检测到漏洞</span>';
            return;
        }

        vulnerabilities.forEach(vuln => {
            const vulnItem = document.createElement('div');
            vulnItem.className = 'vulnerability-item risk-high';
            vulnItem.textContent = vuln;
            container.appendChild(vulnItem);
        });
    }

    // 显示 WHOIS 信息
    function displayWHOISInfo(whoisInfo) {
        const container = document.getElementById('whoisInfo');
        container.innerHTML = '';

        if (Object.keys(whoisInfo).length === 0) {
            container.innerHTML = '<span class="no-data">未获取到 WHOIS 信息</span>';
            return;
        }

        for (const [key, value] of Object.entries(whoisInfo)) {
            if (value && value !== 'None' && value !== '[]') {
                const infoItem = document.createElement('div');
                infoItem.className = 'whois-item';
                infoItem.innerHTML = `
                    <span class="whois-label">${key}:</span>
                    <span class="whois-value">${value}</span>
                `;
                container.appendChild(infoItem);
            }
        }
    }
});