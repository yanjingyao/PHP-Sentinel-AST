import React, { useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { ScanResult, Theme } from '../types';
import { ExportService } from '../services/exportService';

interface DashboardProps {
  scans: ScanResult[];
  theme: Theme;
  onExportScan?: (scan: ScanResult, format: 'html' | 'pdf' | 'json') => void;
}

const Dashboard: React.FC<DashboardProps> = ({ scans, theme }) => {
  const isDark = theme === 'dark';
  const textColor = isDark ? '#a1a1aa' : '#52525b';
  const gridColor = isDark ? '#27272a' : '#e4e4e7';

  // 【UI优化】空状态：增加柔和的渐变发光效果和更优雅的图标
  if (scans.length === 0) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center animate-in fade-in duration-700">
        <div className="relative">
          <div className={`absolute -inset-4 rounded-full blur-xl opacity-50 ${isDark ? 'bg-zinc-800' : 'bg-zinc-200'}`}></div>
          <div className={`relative w-24 h-24 mb-6 rounded-3xl flex items-center justify-center border shadow-lg transition-colors ${isDark ? 'bg-zinc-900 border-zinc-800' : 'bg-white border-zinc-100'}`}>
            <svg className={`w-12 h-12 ${isDark ? 'text-zinc-600' : 'text-zinc-300'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
        </div>
        <h3 className={`text-lg font-semibold mb-2 ${isDark ? 'text-zinc-300' : 'text-zinc-700'}`}>暂无审计数据</h3>
        <p className={`text-sm ${isDark ? 'text-zinc-500' : 'text-zinc-400'}`}>请先执行一次代码扫描，即可在此查看可视化报告</p>
      </div>
    );
  }

  // 保留原有数据逻辑
  const totalStats = scans.reduce((acc, scan) => ({
    critical: acc.critical + scan.stats.critical,
    high: acc.high + scan.stats.high,
    medium: acc.medium + scan.stats.medium,
    low: acc.low + scan.stats.low,
    info: acc.info + (scan.stats.info || 0),
    total: acc.total + scan.stats.total
  }), { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 });

  const riskData = [
    { name: '严重', value: totalStats.critical, color: '#f43f5e' }, // 颜色微调更具现代感
    { name: '高危', value: totalStats.high, color: '#f97316' },
    { name: '中危', value: totalStats.medium, color: '#eab308' },
    { name: '低危', value: totalStats.low, color: '#3b82f6' },
    { name: '提示', value: totalStats.info, color: '#94a3b8' },
  ].filter(d => d.value > 0);

  const typeMap: Record<string, number> = {};
  scans.forEach(scan => {
    scan.vulnerabilities.forEach(v => {
      typeMap[v.type] = (typeMap[v.type] || 0) + 1;
    });
  });

  const typeData = Object.entries(typeMap).map(([name, count]) => ({
    name, count
  })).sort((a, b) => b.count - a.count);

  // 【UI优化】统一卡片基础样式，增加悬浮态和磨砂质感
  const cardStyle = isDark 
    ? 'bg-zinc-900/80 backdrop-blur-md border border-zinc-800/80 text-white shadow-xl shadow-black/10 hover:border-zinc-700/80' 
    : 'bg-white border border-zinc-200 text-zinc-900 shadow-sm hover:shadow-md hover:border-zinc-300/80';
  
  const [isExporting, setIsExporting] = useState(false);
  const [showAllExports, setShowAllExports] = useState(false); // 新增：控制是否显示所有导出项目

  // 保留原有导出逻辑
  const handleExport = async (scan: ScanResult, format: 'html' | 'markdown' | 'json') => {
    setIsExporting(true);
    try {
      if (format === 'html') ExportService.exportToHTML(scan);
      else if (format === 'markdown') ExportService.exportToMarkdown(scan);
      else if (format === 'json') ExportService.exportToJSON(scan);
    } catch (error) {
      console.error('导出失败:', error);
      alert('导出失败，请重试');
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportAll = async (format: 'html' | 'json') => {
    if (scans.length === 0) return;
    setIsExporting(true);
    try {
      const allVulns = scans.flatMap(s => s.vulnerabilities);
      const mergedScan: ScanResult = {
        ...scans[0],
        projectName: 'All-Projects-Merged',
        vulnerabilities: allVulns,
        stats: {
          critical: allVulns.filter(v => v.level === '严重').length,
          high: allVulns.filter(v => v.level === '高危').length,
          medium: allVulns.filter(v => v.level === '中危').length,
          low: allVulns.filter(v => v.level === '低危').length,
          info: allVulns.filter(v => v.level === '提示').length,
          total: allVulns.length,
        }
      };
      if (format === 'html') ExportService.exportToHTML(mergedScan);
      else if (format === 'json') ExportService.exportToJSON(mergedScan);
    } catch (error) {
      console.error('导出失败:', error);
      alert('导出失败，请重试');
    } finally {
      setIsExporting(false);
    }
  };

  // UI配置：顶部四个数据卡的样式配置
  const statCards = [
    { label: '累计扫描漏洞', val: totalStats.total, color: isDark ? 'text-zinc-100' : 'text-zinc-800', bgGlow: 'from-zinc-500/10 to-transparent', icon: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6' },
    { label: '严重威胁', val: totalStats.critical, color: 'text-rose-500', bgGlow: 'from-rose-500/10 to-transparent', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
    { label: '高危风险', val: totalStats.high, color: 'text-orange-500', bgGlow: 'from-orange-500/10 to-transparent', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
    { label: 'AI 已复核', val: scans.flatMap(s => s.vulnerabilities).filter(v => v.aiAssessment).length, color: 'text-emerald-500', bgGlow: 'from-emerald-500/10 to-transparent', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  ];

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-700 pb-8">
      
      {/* 导出功能区 - UI重构 */}
      {scans.length > 0 && (
        <div className={`p-6 rounded-2xl transition-all ${cardStyle}`}>
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-xl ${isDark ? 'bg-zinc-800' : 'bg-zinc-100'}`}>
                <svg className="w-6 h-6 text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-bold tracking-tight">审计报告导出</h3>
                <p className="text-sm text-zinc-500 mt-1">支持导出完整报告或按单个项目导出</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={() => handleExportAll('html')}
                disabled={isExporting}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                  isDark ? 'bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20' : 'bg-emerald-50 text-emerald-600 hover:bg-emerald-100'
                } disabled:opacity-50`}
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                全部 HTML
              </button>
              <button
                onClick={() => handleExportAll('json')}
                disabled={isExporting}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                  isDark ? 'bg-blue-500/10 text-blue-400 hover:bg-blue-500/20' : 'bg-blue-50 text-blue-600 hover:bg-blue-100'
                } disabled:opacity-50`}
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                全部 JSON
              </button>
            </div>
          </div>

          {/* 单个扫描导出 */}
          <div className="mt-6 pt-5 border-t border-zinc-500/20">
            {/* 添加了 max-h 和 overflow-y-auto 防止展开后项目过多撑爆页面高度 */}
            <div className={`flex flex-wrap items-center gap-3 ${showAllExports ? 'max-h-60 overflow-y-auto pr-2 custom-scrollbar' : ''}`}>
              <span className="text-sm font-medium text-zinc-500 mr-2">单项目快捷导出:</span>
              
              {/* 根据状态判断是截取前 5 个还是显示全部 */}
              {(showAllExports ? scans : scans.slice(0, 5)).map((scan) => (
                <div key={scan.id} className={`flex items-center gap-1.5 pl-3 pr-1.5 py-1.5 rounded-lg border ${isDark ? 'border-zinc-700/50 bg-zinc-800/50' : 'border-zinc-200 bg-zinc-50'}`}>
                  <span className="text-xs font-semibold truncate max-w-[120px] mr-1" title={scan.projectName}>
                    {scan.projectName}
                  </span>
                  <button
                    onClick={() => handleExport(scan, 'html')}
                    disabled={isExporting}
                    className={`px-2 py-1 rounded-md text-[10px] font-bold transition-colors ${isDark ? 'bg-zinc-700 text-zinc-300 hover:bg-zinc-600 hover:text-white' : 'bg-zinc-200 text-zinc-600 hover:bg-zinc-300 hover:text-zinc-900'}`}
                  >
                    HTML
                  </button>
                  <button
                    onClick={() => handleExport(scan, 'markdown')}
                    disabled={isExporting}
                    className={`px-2 py-1 rounded-md text-[10px] font-bold transition-colors ${isDark ? 'bg-zinc-700 text-zinc-300 hover:bg-zinc-600 hover:text-white' : 'bg-zinc-200 text-zinc-600 hover:bg-zinc-300 hover:text-zinc-900'}`}
                  >
                    MD
                  </button>
                </div>
              ))}
              
              {/* 可点击的展开/收起按钮 */}
              {scans.length > 5 && (
                <button
                  onClick={() => setShowAllExports(!showAllExports)}
                  className={`text-xs font-medium ml-1 px-2 py-1.5 rounded-md transition-colors cursor-pointer flex items-center gap-1 ${
                    isDark 
                      ? 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800' 
                      : 'text-zinc-500 hover:text-zinc-900 hover:bg-zinc-100'
                  }`}
                >
                  {showAllExports ? '收起' : `+${scans.length - 5} 更多...`}
                  <svg 
                    className={`w-3 h-3 transition-transform ${showAllExports ? 'rotate-180' : ''}`} 
                    fill="none" 
                    viewBox="0 0 24 24" 
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 顶部数据卡片 - UI重构 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6">
        {statCards.map((card, idx) => (
          <div key={idx} className={`relative overflow-hidden p-6 rounded-2xl transition-all duration-300 transform hover:-translate-y-1 ${cardStyle}`}>
            <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl ${card.bgGlow} rounded-bl-[100px] opacity-40`}></div>
            <div className="relative z-10 flex justify-between items-start">
              <div>
                <p className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-2">{card.label}</p>
                <div className="flex items-baseline gap-2">
                  <p className={`text-4xl font-black tracking-tight ${card.color}`}>{card.val}</p>
                </div>
              </div>
              <div className={`p-2 rounded-lg ${isDark ? 'bg-zinc-800/80' : 'bg-zinc-100'}`}>
                <svg className={`w-5 h-5 ${card.color}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={card.icon} />
                </svg>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 图表区 - UI重构 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className={`p-6 sm:p-8 rounded-2xl transition-all ${cardStyle} flex flex-col`}>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-bold tracking-tight">风险等级分布</h3>
              <p className="text-xs text-zinc-500 mt-1">Severity Distribution</p>
            </div>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${isDark ? 'bg-zinc-800' : 'bg-zinc-100'}`}>
              <svg className="w-4 h-4 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" /></svg>
            </div>
          </div>
          <div className="flex-1 min-h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="45%"
                  innerRadius={80}
                  outerRadius={110}
                  paddingAngle={4}
                  dataKey="value"
                  animationBegin={200}
                  animationDuration={1500}
                  stroke="none"
                >
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  cursor={{ fill: 'transparent' }}
                  contentStyle={{ 
                    backgroundColor: isDark ? 'rgba(24, 24, 27, 0.9)' : 'rgba(255, 255, 255, 0.9)', 
                    borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                    borderRadius: '12px', 
                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
                    fontSize: '13px',
                    fontWeight: 500,
                    backdropFilter: 'blur(8px)',
                  }}
                  itemStyle={{ color: isDark ? '#fff' : '#000', padding: '2px 0' }}
                />
                <Legend 
                  verticalAlign="bottom" 
                  height={36} 
                  iconType="circle"
                  wrapperStyle={{ color: textColor, fontSize: '12px', fontWeight: 500, paddingTop: '20px' }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className={`p-6 sm:p-8 rounded-2xl transition-all ${cardStyle} flex flex-col`}>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-bold tracking-tight">漏洞类型排行</h3>
              <p className="text-xs text-zinc-500 mt-1">Top Vulnerability Patterns</p>
            </div>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${isDark ? 'bg-zinc-800' : 'bg-zinc-100'}`}>
              <svg className="w-4 h-4 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" /></svg>
            </div>
          </div>
          <div className="flex-1 min-h-[300px] -ml-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={typeData.slice(0, 7)} layout="vertical" margin={{ top: 5, right: 20, left: 20, bottom: 5 }}>
                <XAxis type="number" hide />
                <YAxis 
                  dataKey="name" 
                  type="category" 
                  width={110} 
                  stroke={textColor} 
                  fontSize={12} 
                  fontWeight={500}
                  tickLine={false} 
                  axisLine={false}
                />
                <Tooltip 
                  cursor={{ fill: isDark ? 'rgba(39, 39, 42, 0.4)' : 'rgba(244, 244, 245, 0.6)' }}
                  contentStyle={{ 
                    backgroundColor: isDark ? 'rgba(24, 24, 27, 0.9)' : 'rgba(255, 255, 255, 0.9)', 
                    borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                    borderRadius: '12px', 
                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
                    fontSize: '13px',
                    fontWeight: 500,
                    backdropFilter: 'blur(8px)',
                  }}
                />
                <Bar 
                  dataKey="count" 
                  fill={isDark ? '#10b981' : '#059669'} 
                  radius={[0, 6, 6, 0]} 
                  barSize={20} 
                  animationDuration={1500} 
                >
                  {typeData.slice(0, 7).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={isDark ? `hsl(160, 80%, ${50 - index * 4}%)` : `hsl(160, 90%, ${40 + index * 5}%)`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;