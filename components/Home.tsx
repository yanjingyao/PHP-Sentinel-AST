import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { ScanResult, Theme } from '../types';

interface HomeProps {
  theme: Theme;
  scans: ScanResult[];
  onTabChange: (tab: string) => void;
  onLoadScan?: (scan: ScanResult) => void;
}

const Home: React.FC<HomeProps> = ({ theme, scans, onTabChange, onLoadScan }) => {
  const isDark = theme === 'dark';

  // 核心样式：超强毛玻璃与柔和投影
  const glassStyle = isDark
    ? 'bg-zinc-900/40 backdrop-blur-3xl border-white/5 shadow-[0_20px_50px_rgba(0,0,0,0.3)]'
    : 'bg-white/60 backdrop-blur-3xl border-white/40 shadow-[0_20px_50px_rgba(31,38,135,0.05)]';

  const textPrimary = isDark ? 'text-white' : 'text-zinc-900';
  const textSecondary = isDark ? 'text-zinc-400' : 'text-zinc-500';

  // 数据逻辑提取
  const totalStats = scans.reduce(
    (acc, scan) => ({
      critical: acc.critical + (scan.stats.critical || 0),
      high: acc.high + (scan.stats.high || 0),
      medium: acc.medium + (scan.stats.medium || 0),
      low: acc.low + (scan.stats.low || 0),
      files: acc.files + (scan.fileCount || 0),
    }),
    { critical: 0, high: 0, medium: 0, low: 0, files: 0 }
  );

  const lastScan = scans[0];

  // ===== 改进 3: 动态安全评分 =====
  const securityScore = useMemo(() => {
    const totalVulns = totalStats.critical + totalStats.high + totalStats.medium + totalStats.low;
    if (totalVulns === 0) return { score: 100, label: '优秀', color: 'emerald' };

    // 扣分权重
    const weights = { critical: 15, high: 8, medium: 3, low: 1 };
    const deduction =
      totalStats.critical * weights.critical +
      totalStats.high * weights.high +
      totalStats.medium * weights.medium +
      totalStats.low * weights.low;

    // 基于文件数量的标准化
    const fileCount = Math.max(totalStats.files, 1);
    const normalizedDeduction = (deduction * 10) / Math.sqrt(fileCount);
    const score = Math.max(0, Math.min(100, Math.round(100 - normalizedDeduction)));

    // 根据分数返回状态
    if (score >= 90) return { score, label: '优秀', color: 'emerald' };
    if (score >= 70) return { score, label: '良好', color: 'blue' };
    if (score >= 50) return { score, label: '一般', color: 'yellow' };
    if (score >= 30) return { score, label: '较差', color: 'orange' };
    return { score, label: '危险', color: 'rose' };
  }, [totalStats]);

  // 获取评分颜色类名
  const getScoreColorClass = (color: string) => {
    const colorMap: Record<string, { text: string; bg: string; border: string }> = {
      emerald: { text: isDark ? 'text-emerald-400' : 'text-emerald-600', bg: 'bg-emerald-500', border: 'border-emerald-500/30' },
      blue: { text: isDark ? 'text-blue-400' : 'text-blue-600', bg: 'bg-blue-500', border: 'border-blue-500/30' },
      yellow: { text: isDark ? 'text-yellow-400' : 'text-yellow-600', bg: 'bg-yellow-500', border: 'border-yellow-500/30' },
      orange: { text: isDark ? 'text-orange-400' : 'text-orange-600', bg: 'bg-orange-500', border: 'border-orange-500/30' },
      rose: { text: isDark ? 'text-rose-400' : 'text-rose-600', bg: 'bg-rose-500', border: 'border-rose-500/30' },
    };
    return colorMap[color] || colorMap.emerald;
  };

  const scoreColors = getScoreColorClass(securityScore.color);

  // ===== 改进 2: 漏洞类型分布数据 =====
  const typeDistribution = useMemo(() => {
    const typeMap: Record<string, number> = {};
    scans.forEach((scan) => {
      scan.vulnerabilities?.forEach((v) => {
        typeMap[v.type] = (typeMap[v.type] || 0) + 1;
      });
    });

    // 漏洞类型颜色映射
    const typeColors: Record<string, string> = {
      'SQL 注入': '#f43f5e',
      '跨站脚本攻击 (XSS)': '#f97316',
      '远程代码执行 (RCE)': '#ef4444',
      '文件包含 (LFI/RFI)': '#eab308',
      '敏感函数调用': '#8b5cf6',
      '不可信输入源': '#06b6d4',
      '服务端请求伪造 (SSRF)': '#ec4899',
      '不安全的反序列化': '#f59e0b',
      '路径穿越/任意文件操作': '#84cc16',
      '弱加密/哈希算法': '#64748b',
      'HTTP 头部注入': '#14b8a6',
      'LDAP 注入': '#a855f7',
      '不安全的文件上传': '#d946ef',
      'Webshell 恶意后门': '#dc2626',
      '自定义规则': '#6366f1',
    };

    return Object.entries(typeMap)
      .map(([name, value]) => ({
        name: name.length > 8 ? name.slice(0, 8) + '...' : name,
        fullName: name,
        value,
        color: typeColors[name] || '#64748b',
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);
  }, [scans]);

  // 图表颜色配置
  const textColor = isDark ? '#a1a1aa' : '#52525b';

  // ===== 改进 4: 快捷功能导航配置 =====
  const quickNavs = [
    {
      id: 'scan',
      title: '代码审计',
      desc: 'AST 深度扫描',
      icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
      color: 'emerald',
    },
    {
      id: 'webshell',
      title: 'WebShell 检测',
      desc: '恶意后门识别',
      icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
      color: 'rose',
    },
    {
      id: 'dashboard',
      title: '完整报表',
      desc: '可视化分析',
      icon: 'M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z',
      color: 'blue',
    },
    {
      id: 'rules',
      title: '规则配置',
      desc: '自定义检测规则',
      icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z',
      color: 'purple',
    },
  ];

  const getQuickNavColor = (color: string) => {
    const colorMap: Record<string, { bg: string; text: string; hover: string }> = {
      emerald: {
        bg: isDark ? 'bg-emerald-500/10' : 'bg-emerald-50',
        text: isDark ? 'text-emerald-400' : 'text-emerald-600',
        hover: 'group-hover:border-emerald-500/30',
      },
      rose: {
        bg: isDark ? 'bg-rose-500/10' : 'bg-rose-50',
        text: isDark ? 'text-rose-400' : 'text-rose-600',
        hover: 'group-hover:border-rose-500/30',
      },
      blue: {
        bg: isDark ? 'bg-blue-500/10' : 'bg-blue-50',
        text: isDark ? 'text-blue-400' : 'text-blue-600',
        hover: 'group-hover:border-blue-500/30',
      },
      purple: {
        bg: isDark ? 'bg-purple-500/10' : 'bg-purple-50',
        text: isDark ? 'text-purple-400' : 'text-purple-600',
        hover: 'group-hover:border-purple-500/30',
      },
    };
    return colorMap[color] || colorMap.emerald;
  };

  return (
    <div className="relative min-h-screen px-6 py-12 lg:px-20 lg:py-16 overflow-hidden font-sans">
      {/* 动态流体背景层 - 增加色彩层次 */}
      <div className="absolute inset-0 -z-10">
        <div
          className={`absolute top-[-20%] left-[-10%] w-[60%] h-[60%] rounded-full blur-[140px] opacity-40 animate-pulse ${
            isDark ? 'bg-emerald-900/30' : 'bg-emerald-100'
          }`}
        />
        <div
          className={`absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full blur-[140px] opacity-30 ${
            isDark ? 'bg-blue-900/30' : 'bg-blue-100'
          }`}
        />
        <div
          className={`absolute top-[30%] right-[20%] w-[30%] h-[30%] rounded-full blur-[120px] opacity-20 ${
            isDark ? 'bg-purple-900/20' : 'bg-purple-100'
          }`}
        />
      </div>

      <div className="max-w-7xl mx-auto space-y-16">
        {/* --- 第一部分：品牌与核心语 --- */}
        <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-12">
          <div className="space-y-6">
            <div className="inline-flex items-center gap-3 px-4 py-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/5 text-emerald-500 text-[10px] font-black uppercase tracking-[0.3em]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              Sentinel AST 引擎已就绪
            </div>
            <h1 className={`text-7xl lg:text-8xl font-extralight tracking-tighter leading-none ${textPrimary}`}>
              安全<span className="font-black text-emerald-500">.</span>
              <br />
              始于代码
            </h1>
            <p className={`max-w-md text-lg font-medium leading-relaxed opacity-60 ${textSecondary}`}>
              利用 AST 深度解析与 AI 联觉技术，将复杂的代码审计转化为直观的视觉洞察。
            </p>
          </div>

          {/* 核心动作按钮 */}
          <div className="flex flex-col sm:flex-row gap-4">
            <button
              onClick={() => onTabChange('scan')}
              className="group relative px-12 py-6 rounded-[2rem] bg-zinc-900 dark:bg-white text-white dark:text-zinc-900 font-bold transition-all hover:scale-105 hover:shadow-[0_20px_40px_rgba(0,0,0,0.2)] active:scale-95 overflow-hidden"
            >
              <span className="relative z-10 text-lg">开始深度审计</span>
              <div className="absolute inset-0 bg-gradient-to-r from-emerald-400 to-teal-400 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
            </button>
            <button
              onClick={() => onTabChange('webshell')}
              className={`px-12 py-6 rounded-[2rem] border font-bold transition-all hover:bg-white/10 ${
                isDark ? 'border-white/10' : 'border-zinc-200'
              }`}
            >
              Webshell 扫描
            </button>
          </div>
        </section>

        {/* --- 改进 4: 快捷功能导航 --- */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {quickNavs.map((nav) => {
            const colors = getQuickNavColor(nav.color);
            return (
              <button
                key={nav.id}
                onClick={() => onTabChange(nav.id)}
                className={`group p-6 rounded-3xl border transition-all duration-300 hover:-translate-y-1 ${glassStyle} ${colors.hover} text-left`}
              >
                <div
                  className={`w-12 h-12 rounded-2xl ${colors.bg} ${colors.text} flex items-center justify-center mb-4 transition-transform group-hover:scale-110`}
                >
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={nav.icon} />
                  </svg>
                </div>
                <h3 className={`text-sm font-bold mb-1 ${textPrimary}`}>{nav.title}</h3>
                <p className={`text-xs ${textSecondary}`}>{nav.desc}</p>
                <div className="mt-3 flex items-center text-[10px] font-black uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-opacity">
                  <span className={colors.text}>进入</span>
                  <svg className={`w-3 h-3 ml-1 ${colors.text}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </button>
            );
          })}
        </section>

        {/* --- 第二部分：沉浸式统计 (玻璃网格) --- */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* 大卡片：总体态势 */}
          <div className={`md:col-span-2 p-10 rounded-[3rem] border ${glassStyle} flex flex-col justify-between min-h-[380px]`}>
            <div className="flex justify-between items-start">
              <span className="text-[10px] font-black uppercase tracking-[0.4em] opacity-40">安全态势概览</span>
              <div className="text-right">
                <p className={`text-4xl font-light italic ${scoreColors.text}`}>{securityScore.label}</p>
                <p className="text-[10px] font-bold opacity-30 uppercase">系统完整性指标</p>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 items-end">
              <div>
                <p className="text-5xl font-black tracking-tighter">{totalStats.critical + totalStats.high + totalStats.medium + totalStats.low}</p>
                <p className="text-[10px] font-black uppercase opacity-30 mt-2">累计发现缺陷</p>
              </div>
              <div>
                <p className="text-5xl font-black tracking-tighter text-rose-500">{totalStats.critical}</p>
                <p className="text-[10px] font-black uppercase opacity-30 mt-2">严重安全威胁</p>
              </div>
              <div>
                <p className="text-5xl font-black tracking-tighter text-orange-500">{totalStats.high}</p>
                <p className="text-[10px] font-black uppercase opacity-30 mt-2">高危风险</p>
              </div>
              <div className="pb-2">
                <div className="h-1 bg-zinc-200 dark:bg-zinc-800 w-full rounded-full overflow-hidden">
                  <div className={`h-full ${scoreColors.bg}`} style={{ width: `${securityScore.score}%` }} />
                </div>
                <p className={`text-[10px] font-black uppercase mt-3 ${scoreColors.text}`}>
                  加权安全评分 {securityScore.score}%
                </p>
              </div>
            </div>
          </div>

          {/* 改进 2: 漏洞类型分布图 */}
          <div className={`p-8 rounded-[3rem] border ${glassStyle} flex flex-col min-h-[380px]`}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold tracking-tight">漏洞类型分布</h3>
                <p className="text-[10px] text-zinc-500 mt-0.5">Vulnerability Types</p>
              </div>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${isDark ? 'bg-zinc-800' : 'bg-zinc-100'}`}>
                <svg className="w-4 h-4 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
                </svg>
              </div>
            </div>

            {typeDistribution.length > 0 ? (
              <div className="flex-1 min-h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={typeDistribution}
                      cx="50%"
                      cy="40%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={3}
                      dataKey="value"
                      stroke="none"
                    >
                      {typeDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: isDark ? 'rgba(24, 24, 27, 0.9)' : 'rgba(255, 255, 255, 0.9)',
                        borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                        borderRadius: '12px',
                        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
                        fontSize: '12px',
                        backdropFilter: 'blur(8px)',
                      }}
                      itemStyle={{ color: isDark ? '#fff' : '#000' }}
                      formatter={(value: number, name: string, props: any) => [value, props?.payload?.fullName || name]}
                    />
                    <Legend
                      verticalAlign="bottom"
                      height={60}
                      iconType="circle"
                      wrapperStyle={{ color: textColor, fontSize: '10px', fontWeight: 500 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-center">
                <div className={`w-16 h-16 rounded-2xl ${isDark ? 'bg-zinc-800' : 'bg-zinc-100'} flex items-center justify-center mb-4`}>
                  <svg className={`w-8 h-8 ${isDark ? 'text-zinc-600' : 'text-zinc-400'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <p className={`text-xs ${textSecondary}`}>暂无漏洞数据</p>
              </div>
            )}
          </div>
        </section>

        {/* --- 第三部分：最近项目 (优雅的横向流) --- */}
        <section className="space-y-10">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-black uppercase tracking-[0.5em] opacity-30">活跃情报源</h3>
            <div className="h-[1px] flex-1 mx-8 bg-gradient-to-r from-transparent via-zinc-500/20 to-transparent" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {scans.slice(0, 4).map((scan, i) => (
              <div
                key={i}
                onClick={() => onLoadScan?.(scan)}
                className={`p-8 rounded-[2.5rem] border transition-all hover:-translate-y-2 group cursor-pointer ${glassStyle}`}
              >
                <div className="flex justify-between items-start mb-12">
                  <div
                    className={`text-[10px] font-mono px-2 py-1 rounded border ${
                      isDark ? 'border-white/10' : 'border-zinc-200'
                    }`}
                  >
                    NO.0{i + 1}
                  </div>
                  <div
                    className={`w-2 h-2 rounded-full ${
                      scan.stats.critical > 0
                        ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]'
                        : scan.stats.high > 0
                        ? 'bg-orange-500'
                        : scan.stats.total > 0
                        ? 'bg-yellow-500'
                        : 'bg-emerald-500'
                    }`}
                  />
                </div>

                {/* 漏洞统计摘要 */}
                <div className="flex gap-2 mb-4">
                  {scan.stats.critical > 0 && (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-500">
                      严 {scan.stats.critical}
                    </span>
                  )}
                  {scan.stats.high > 0 && (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-500">
                      高 {scan.stats.high}
                    </span>
                  )}
                  {scan.stats.total === 0 && (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-500">
                      安全
                    </span>
                  )}
                </div>

                <div>
                  <h4 className="text-lg font-bold tracking-tight truncate">{scan.projectName}</h4>
                  <div className="flex items-center justify-between mt-2">
                    <p className="text-[10px] font-black uppercase opacity-30 tracking-widest">
                      {new Date(scan.timestamp).toLocaleDateString()}
                    </p>
                    <span className="text-xs font-bold text-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity">
                      加载
                    </span>
                  </div>
                </div>
              </div>
            ))}

            {/* 占位符：添加新项目 */}
            <button
              onClick={() => onTabChange('scan')}
              className={`p-8 rounded-[2.5rem] border border-dashed flex flex-col items-center justify-center gap-4 transition-all hover:bg-white/5 ${
                isDark ? 'border-white/10 opacity-30' : 'border-zinc-300 opacity-60'
              }`}
            >
              <div className="w-10 h-10 rounded-full border border-current flex items-center justify-center">
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
              </div>
              <span className="text-xs font-black uppercase tracking-widest">启动新审计</span>
            </button>
          </div>
        </section>

        {/* --- 第四部分：系统遥测 (页脚) --- */}
        <footer className={`p-8 rounded-[2rem] border ${glassStyle} flex flex-wrap justify-between items-center gap-6`}>
          <div className="flex gap-12">
            <div className="space-y-1">
              <p className="text-[10px] font-black opacity-30 uppercase">引擎状态</p>
              <p className="text-xs font-bold text-emerald-500">运行良好 (OPERATIONAL)</p>
            </div>
            <div className="space-y-1">
              <p className="text-[10px] font-black opacity-30 uppercase">最后一次审计</p>
              <p className="text-xs font-bold">{lastScan ? lastScan.projectName : '暂无记录'}</p>
            </div>
            <div className="space-y-1 hidden sm:block">
              <p className="text-[10px] font-black opacity-30 uppercase">数据同步</p>
              <p className="text-xs font-bold">本地集簇 + 云端加密备份</p>
            </div>
          </div>
          <div className="text-[10px] font-mono opacity-20 uppercase tracking-[0.2em]">Sentinel.Protocol // 核心版本 2.4.0-Alpha</div>
        </footer>
      </div>

      {/* 隐藏滚动条 */}
      <style
        dangerouslySetInnerHTML={{
          __html: `
        ::-webkit-scrollbar { width: 0px; background: transparent; }
        body { scroll-behavior: smooth; }
      `,
        }}
      />
    </div>
  );
};

export default Home;
