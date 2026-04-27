import { ScanResult, Vulnerability, RiskLevel } from '../types';

/**
 * 导出服务 - 支持 Markdown、HTML、JSON 格式导出
 */
export class ExportService {
  /**
   * 生成扫描报告的 HTML 内容
   */
  static generateReportHTML(scan: ScanResult): string {
    const date = new Date(scan.timestamp).toLocaleString('zh-CN');

    // 统计 AI 审计情况
    const auditedCount = scan.vulnerabilities.filter(v => v.aiAssessment && !v.aiAssessment.error).length;
    const falsePositiveCount = scan.vulnerabilities.filter(v => v.aiAssessment?.isFalsePositive).length;
    const confirmedCount = auditedCount - falsePositiveCount;

    const vulnerabilitiesHTML = scan.vulnerabilities.map((v, i) => {
      // AI 审计结果展示
      let aiResultHTML = '';
      if (v.aiAssessment) {
        if (v.aiAssessment.error) {
          aiResultHTML = `
            <div class="ai-box ai-error">
              <div class="ai-header">❌ AI 审计失败</div>
              <div class="ai-content">${this.escapeHtml(v.aiAssessment.error)}</div>
            </div>
          `;
        } else {
          const isFp = v.aiAssessment.isFalsePositive;
          aiResultHTML = `
            <div class="ai-box ${isFp ? 'ai-warning' : 'ai-success'}">
              <div class="ai-header">
                ${isFp ? '⚠️ AI 判定为误报 (False Positive)' : '✅ AI 已确认漏洞存在'}
              </div>
              ${v.aiAssessment.rawReport ? `<div class="ai-content">${this.escapeHtml(v.aiAssessment.rawReport)}</div>` : ''}
              
              ${v.aiAssessment.poc ? `
                <div class="ai-snippet-box">
                  <div class="ai-snippet-title">💡 验证方法 (PoC):</div>
                  <code>${this.escapeHtml(v.aiAssessment.poc)}</code>
                </div>
              ` : ''}
              
              ${v.aiAssessment.payload ? `
                <div class="ai-snippet-box payload-box">
                  <div class="ai-snippet-title">💣 攻击载荷 (Payload):</div>
                  <code>${this.escapeHtml(v.aiAssessment.payload)}</code>
                </div>
              ` : ''}
            </div>
          `;
        }
      } else {
        aiResultHTML = `
          <div class="ai-box ai-pending">
            ⏳ AI 未审计结果...
          </div>
        `;
      }

      return `
        <div class="vuln-card">
          <div class="vuln-header">
            <h3 class="vuln-title">
              <span class="vuln-id">#${i + 1}</span> ${v.type}
            </h3>
            <span class="badge" style="background-color: ${this.getRiskColor(v.level)};">
              ${v.level}
            </span>
          </div>

          <div class="vuln-meta">
            <strong>📁 文件位置:</strong> 
            <span class="file-path">${v.fileName}</span> 
            <span class="line-number">(第 ${v.line} 行)</span>
          </div>

          <p class="vuln-desc">${v.description}</p>

          <div class="code-block">
            <div class="code-header">易受攻击的代码片段</div>
            <pre><code>${this.escapeHtml(v.snippet)}</code></pre>
          </div>

          ${aiResultHTML}
        </div>
      `;
    }).join('');

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PHP Sentinel 扫描报告 - ${scan.projectName}</title>
  <style>
    :root {
      --bg-color: #f8fafc;
      --card-bg: #ffffff;
      --text-main: #334155;
      --text-muted: #64748b;
      --border-color: #e2e8f0;
      --primary: #0f172a;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.6;
      color: var(--text-main);
      background-color: var(--bg-color);
      padding: 32px 20px;
    }
    
    .container {
      max-width: 1040px;
      margin: 0 auto;
    }

    /* Header Section */
    .header {
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: white;
      padding: 40px 32px;
      border-radius: 20px;
      margin-bottom: 32px;
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .header h1 { font-size: 32px; font-weight: 800; letter-spacing: -0.02em; display: flex; align-items: center; gap: 12px; }
    .header .meta { display: flex; flex-wrap: wrap; gap: 16px; font-size: 14px; opacity: 0.9; }
    .header .meta span { display: flex; align-items: center; gap: 6px; background: rgba(255,255,255,0.1); padding: 6px 14px; border-radius: 100px; }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }
    .stat-card {
      background: var(--card-bg);
      padding: 24px 20px;
      border-radius: 16px;
      border: 1px solid var(--border-color);
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
      display: flex;
      flex-direction: column;
      align-items: center;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
    }
    .stat-card.critical::before { background-color: #e11d48; }
    .stat-card.high::before { background-color: #ea580c; }
    .stat-card.medium::before { background-color: #ca8a04; }
    .stat-card.low::before { background-color: #2563eb; }
    .stat-card.total::before { background-color: #475569; }
    
    .stat-value { font-size: 36px; font-weight: 900; line-height: 1; margin-bottom: 8px; }
    .stat-label { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

    /* AI Summary */
    .ai-summary {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 40px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 24px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    }
    .ai-stat-item { display: flex; align-items: center; gap: 16px; }
    .ai-icon-wrap { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 20px; }
    .ai-stat-info { display: flex; flex-direction: column; }
    .ai-stat-info .num { font-size: 24px; font-weight: 800; line-height: 1; color: var(--text-main); }
    .ai-stat-info .lbl { font-size: 13px; color: var(--text-muted); margin-top: 4px; font-weight: 500; }

    /* Section Title */
    .section-title {
      font-size: 24px; font-weight: 800; margin-bottom: 24px; color: var(--primary);
      display: flex; align-items: center; gap: 12px; padding-bottom: 16px; border-bottom: 2px solid var(--border-color);
    }

    /* Vulnerability Cards */
    .vuln-card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 28px;
      margin-bottom: 24px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .vuln-card:hover { box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); }
    
    .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px; }
    .vuln-title { font-size: 20px; font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 12px; }
    .vuln-id { color: #94a3b8; font-size: 18px; font-weight: 500; }
    .badge { padding: 6px 16px; border-radius: 100px; color: white; font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    
    .vuln-meta { background: #f1f5f9; padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 20px; color: #475569; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .vuln-meta .file-path { font-family: ui-monospace, monospace; color: #0f172a; font-weight: 500; }
    .vuln-meta .line-number { color: #64748b; font-size: 13px; }
    
    .vuln-desc { font-size: 15px; color: #334155; margin-bottom: 20px; line-height: 1.7; }

    /* Code Block */
    .code-block { background: #1e293b; border-radius: 12px; overflow: hidden; margin-bottom: 24px; }
    .code-header { background: #0f172a; color: #94a3b8; font-size: 12px; padding: 10px 16px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .code-block pre { margin: 0; padding: 20px; overflow-x: auto; }
    .code-block code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 14px; color: #e2e8f0; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }

    /* AI Box */
    .ai-box { padding: 20px; border-radius: 12px; margin-top: 16px; border: 1px solid transparent; }
    .ai-header { font-size: 15px; font-weight: 700; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
    .ai-content { font-size: 14px; line-height: 1.7; margin-bottom: 16px; }
    
    .ai-success { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
    .ai-warning { background: #fffbeb; border-color: #fde68a; color: #92400e; }
    .ai-error { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
    .ai-pending { background: #f8fafc; border-color: #e2e8f0; color: #64748b; font-weight: 500; display: flex; align-items: center; justify-content: center; padding: 16px;}

    .ai-snippet-box { background: rgba(0,0,0,0.04); padding: 12px 16px; border-radius: 8px; margin-top: 12px; }
    .payload-box { background: rgba(220, 38, 38, 0.05); border: 1px dashed rgba(220, 38, 38, 0.2); }
    .ai-snippet-title { font-size: 12px; font-weight: 700; margin-bottom: 8px; opacity: 0.8; }
    .ai-snippet-box code { font-family: ui-monospace, monospace; font-size: 13px; display: block; white-space: pre-wrap; word-break: break-all; }

    /* Footer */
    .footer { text-align: center; margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border-color); color: var(--text-muted); font-size: 14px; }
    
    @media print {
      body { background: white; padding: 0; }
      .container { max-width: 100%; }
      .header { border-radius: 0; box-shadow: none; padding: 24px; color: black; background: #f8fafc; border-bottom: 2px solid #0f172a; }
      .header h1 { color: #0f172a; }
      .header .meta span { color: #475569; background: none; padding: 0; }
      .vuln-card { break-inside: avoid; box-shadow: none; border-color: #cbd5e1; }
      .code-block, .ai-box { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> PHP Sentinel 安全审计报告</h1>
      <div class="meta">
        <span>📁 项目: ${scan.projectName}</span>
        <span>🕐 时间: ${date}</span>
        <span>🔍 模式: ${scan.isWebshellScan ? 'Webshell 检测' : '代码常规审计'}</span>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card critical">
        <div class="stat-value" style="color: #e11d48;">${scan.stats.critical}</div>
        <div class="stat-label">严重威胁</div>
      </div>
      <div class="stat-card high">
        <div class="stat-value" style="color: #ea580c;">${scan.stats.high}</div>
        <div class="stat-label">高危风险</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-value" style="color: #ca8a04;">${scan.stats.medium}</div>
        <div class="stat-label">中危风险</div>
      </div>
      <div class="stat-card low">
        <div class="stat-value" style="color: #2563eb;">${scan.stats.low}</div>
        <div class="stat-label">低危风险</div>
      </div>
      <div class="stat-card total">
        <div class="stat-value" style="color: #0f172a;">${scan.stats.total}</div>
        <div class="stat-label">累计漏洞</div>
      </div>
    </div>

    <div class="ai-summary">
      <div class="ai-stat-item">
        <div class="ai-icon-wrap" style="background: #e0f2fe; color: #0284c7;">🤖</div>
        <div class="ai-stat-info"><span class="num">${auditedCount}</span><span class="lbl">AI 已复核</span></div>
      </div>
      <div class="ai-stat-item">
        <div class="ai-icon-wrap" style="background: #dcfce3; color: #16a34a;">✅</div>
        <div class="ai-stat-info"><span class="num">${confirmedCount}</span><span class="lbl">真实威胁确认</span></div>
      </div>
      <div class="ai-stat-item">
        <div class="ai-icon-wrap" style="background: #fef3c7; color: #d97706;">⚠️</div>
        <div class="ai-stat-info"><span class="num">${falsePositiveCount}</span><span class="lbl">误报过滤</span></div>
      </div>
      <div class="ai-stat-item">
        <div class="ai-icon-wrap" style="background: #f1f5f9; color: #475569;">⏳</div>
        <div class="ai-stat-info"><span class="num">${scan.vulnerabilities.length - auditedCount}</span><span class="lbl">队列中/待定</span></div>
      </div>
    </div>

    <div class="section-title">
      🐛 漏洞详细档案 (${scan.vulnerabilities.length} 个)
    </div>
    
    <div class="vuln-list">
      ${vulnerabilitiesHTML || `
        <div style="text-align: center; padding: 60px 20px; background: white; border-radius: 16px; border: 1px dashed #cbd5e1;">
          <div style="font-size: 48px; margin-bottom: 16px;">🎉</div>
          <h3 style="color: #0f172a; margin-bottom: 8px;">完美！未发现任何漏洞</h3>
          <p style="color: #64748b;">您的代码目前看起来非常安全。</p>
        </div>
      `}
    </div>

    <div class="footer">
      <p><strong>PHP Sentinel</strong> | Advanced AST-based Vulnerability Detection Engine</p>
      <p style="margin-top: 8px; font-size: 12px; opacity: 0.7;">报告自动生成于 ${new Date().toLocaleString('zh-CN')}</p>
    </div>
  </div>
</body>
</html>`;
  }

  /**
   * 获取风险等级对应的颜色
   */
  private static getRiskColor(level: RiskLevel): string {
    switch (level) {
      case RiskLevel.CRITICAL: return '#e11d48'; // 优化颜色至现代感红
      case RiskLevel.HIGH: return '#ea580c';     // 现代感橙
      case RiskLevel.MEDIUM: return '#ca8a04';   // 现代感黄
      case RiskLevel.LOW: return '#2563eb';      // 现代感蓝
      case RiskLevel.INFO: return '#64748b';
      default: return '#64748b';
    }
  }

  /**
   * 导出为 HTML 文件
   */
  static exportToHTML(scan: ScanResult): void {
    const html = this.generateReportHTML(scan);
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    this.downloadFile(blob, `PHP-Sentinel-Report-${scan.projectName}-${Date.now()}.html`);
  }

  /**
   * 导出为 JSON 文件
   */
  static exportToJSON(scan: ScanResult): void {
    const data = {
      exportVersion: '1.0',
      exportTime: new Date().toISOString(),
      scan,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    this.downloadFile(blob, `PHP-Sentinel-Data-${scan.projectName}-${Date.now()}.json`);
  }

  /**
   * 导出为 Markdown 文件
   * 生成 Markdown 格式的审计报告 (排版与可读性优化版)
   */
  static exportToMarkdown(scan: ScanResult): void {
    const date = new Date(scan.timestamp).toLocaleString('zh-CN');
    const auditedCount = scan.vulnerabilities.filter(v => v.aiAssessment && !v.aiAssessment.error).length;
    const confirmedCount = scan.vulnerabilities.filter(v => v.aiAssessment?.isFalsePositive === false).length;
    const fpCount = scan.vulnerabilities.filter(v => v.aiAssessment?.isFalsePositive === true).length;

    // 生成漏洞详情
    const vulnsMarkdown = scan.vulnerabilities.map((v, i) => {
      let aiSection = '';
      if (v.aiAssessment) {
        if (v.aiAssessment.error) {
          aiSection = `\n> **❌ AI 审计失败**\n> \n> ${v.aiAssessment.error}\n`;
        } else {
          const isFp = v.aiAssessment.isFalsePositive;
          aiSection = `\n> **${isFp ? '⚠️ AI 判定为误报 (False Positive)' : '✅ AI 已确认漏洞'}**\n`;
          
          if (v.aiAssessment.rawReport) {
            // 将分析报告的每一行前面加上引用符号，保持格式优美
            const reportText = v.aiAssessment.rawReport.split('\n').map(line => `> ${line}`).join('\n');
            aiSection += `>\n> **📝 分析报告:**\n${reportText}\n`;
          }
          if (v.aiAssessment.poc) {
            aiSection += `>\n> **💡 验证方法 (PoC):**\n> \`\`\`bash\n> ${v.aiAssessment.poc.replace(/\n/g, '\n> ')}\n> \`\`\`\n`;
          }
          if (v.aiAssessment.payload) {
            aiSection += `>\n> **💣 攻击载荷 (Payload):**\n> \`\`\`text\n> ${v.aiAssessment.payload.replace(/\n/g, '\n> ')}\n> \`\`\`\n`;
          }
        }
      } else {
        aiSection = `\n> **⏳ 等待 AI 审计中...**\n`;
      }

      return `---

### 🛑 漏洞 #${i + 1}: ${v.type}

**基本信息**

- **风险等级**: \`${v.level}\`
- **文件位置**: \`${v.fileName}\` (第 **${v.line}** 行)
- **污染来源 (Source)**: \`${v.source}\`
- **执行终点 (Sink)**: \`${v.sink}\`

**详细描述**

${v.description}

**🚨 易受攻击代码片段**

\`\`\`php
${v.snippet}
\`\`\`

**🤖 AI 审计结果**
${aiSection}`;
    }).join('\n');

    const markdown = `# 🔒 PHP Sentinel 安全审计报告

> **生成时间**: ${date}
> **扫描模式**: ${scan.isWebshellScan ? 'Webshell 检测' : '代码常规审计'}
> **项目名称**: \`${scan.projectName}\`

---

## 📊 风险数据统计

| 🔴 严重 | 🟠 高危 | 🟡 中危 | 🔵 低危 | 📝 总计 |
| :---: | :---: | :---: | :---: | :---: |
| **${scan.stats.critical}** | **${scan.stats.high}** | **${scan.stats.medium}** | **${scan.stats.low}** | **${scan.stats.total}** |

## 🤖 AI 复核概览

| 状态 | 数量 | 描述 |
| :--- | :---: | :--- |
| **🔍 已审计** | \`${auditedCount}\` | AI 成功完成分析的漏洞数量 |
| **✅ 已确认** | \`${confirmedCount}\` | 确认为真实威胁的漏洞数量 |
| **⚠️ 判定误报**| \`${fpCount}\` | AI 判定为 False Positive 的数量 |
| **⏳ 待复核** | \`${scan.vulnerabilities.length - auditedCount}\` | 队列中等待分析的数量 |

---

## 🐛 漏洞档案详情 (共 ${scan.vulnerabilities.length} 个)
${vulnsMarkdown || '\n*🎉 恭喜！本次扫描未发现任何安全漏洞。*\n'}

---
*Generated by **PHP Sentinel** | Advanced AST-based Vulnerability Detection Engine*
`;

    const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
    this.downloadFile(blob, `PHP-Sentinel-Report-${scan.projectName}-${Date.now()}.md`);
  }

  /**
   * 导出规则为 JSON
   */
  static exportRules(rules: any[]): void {
    const data = {
      exportVersion: '1.0',
      exportTime: new Date().toISOString(),
      type: 'rules',
      rules,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    this.downloadFile(blob, `PHP-Sentinel-Rules-${Date.now()}.json`);
  }

  /**
   * 导入规则从 JSON
   */
  static async importRules(file: File): Promise<any[]> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const data = JSON.parse(e.target?.result as string);
          if (data.type === 'rules' && Array.isArray(data.rules)) {
            resolve(data.rules);
          } else {
            reject(new Error('Invalid rule file format'));
          }
        } catch (error) {
          reject(new Error('Failed to parse rule file'));
        }
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  }

  /**
   * 导出配置
   */
  static exportConfig(config: any, name: string): void {
    const data = {
      exportVersion: '1.0',
      exportTime: new Date().toISOString(),
      type: 'config',
      name,
      config,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    this.downloadFile(blob, `PHP-Sentinel-Config-${name}-${Date.now()}.json`);
  }

  /**
   * 导入配置
   */
  static async importConfig(file: File): Promise<{ name: string; config: any }> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const data = JSON.parse(e.target?.result as string);
          if (data.type === 'config' && data.config) {
            resolve({ name: data.name || 'Imported', config: data.config });
          } else {
            reject(new Error('Invalid config file format'));
          }
        } catch (error) {
          reject(new Error('Failed to parse config file'));
        }
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  }

  /**
   * 通用下载文件方法
   */
  private static downloadFile(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  /**
   * HTML 转义
   */
  private static escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}