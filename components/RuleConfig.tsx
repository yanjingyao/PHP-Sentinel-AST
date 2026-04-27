import { useState, useEffect, useMemo, useRef } from 'react';
import { Rule, RiskLevel, VulnerabilityType, Theme } from '../types';
import { BUILT_IN_RULES } from '../services/builtInRules';
import { rulesApi } from '../frontend/src/api';
import { ExportService } from '../services/exportService';

interface RuleConfigProps {
  theme: Theme;
}

type RuleCategory = 'general' | 'webshell';

const RULE_TEMPLATES = [
  { name: 'SQLi: PDO 注入', pattern: '(PDO::query|PDO::prepare)\\(.*?(\\$.*?)\\)', type: VulnerabilityType.SQL_INJECTION, level: RiskLevel.CRITICAL },
  { name: 'Upload: 文件保存', pattern: 'move_uploaded_file\\(.*?(\\$.*?)\\)', type: VulnerabilityType.FILE_UPLOAD, level: RiskLevel.CRITICAL },
  { name: 'XSS: 隐式打印', pattern: '(vprintf|print_r|var_dump)\\s*?\\(.*?(\\$.*?)\\)', type: VulnerabilityType.XSS, level: RiskLevel.HIGH },
  { name: 'Webshell: 冰蝎流量', pattern: 'eval\\(base64_decode\\(\\$_(POST|GET)', type: VulnerabilityType.WEBSHELL, level: RiskLevel.CRITICAL },
];

const RuleConfig: React.FC<RuleConfigProps> = ({ theme }) => {
  const isDark = theme === 'dark';
  const [activeCategory, setActiveCategory] = useState<RuleCategory>('general');
  const [rules, setRules] = useState<Rule[]>([]);
  const [testCode, setTestCode] = useState('<?php\n// 测试代码\nmove_uploaded_file($_FILES["file"]["tmp_name"], "uploads/" . $_FILES["file"]["name"]);\n$pdo->query("SELECT * FROM news WHERE id = " . $_GET["id"]);');
  const [testResult, setTestResult] = useState<{ match: string; line: number }[]>([]);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [newRule, setNewRule] = useState<Partial<Rule>>({
    name: '',
    pattern: '',
    level: RiskLevel.MEDIUM,
    type: VulnerabilityType.CUSTOM,
    enabled: true,
    isBuiltIn: false
  });
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<Rule>>({});

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      const customResponse = await rulesApi.getAll();
      const customRules: Rule[] = customResponse.data.map((r: any) => ({
        ...r,
        isBuiltIn: false
      }));

      const statesResponse = await rulesApi.getStates();
      const dbRuleStates: Record<string, boolean> = statesResponse.data;
      
      const localStates = localStorage.getItem('phpsentinel_rule_states');
      const localRuleStates: Record<string, boolean> = localStates ? JSON.parse(localStates) : {};
      
      const mergedStates = { ...localRuleStates, ...dbRuleStates };

      const builtInWithStates = BUILT_IN_RULES.map(r => ({
        ...r,
        enabled: mergedStates[r.id] !== undefined ? mergedStates[r.id] : r.enabled
      }));

      const customRulesWithStates = customRules.map(r => ({
        ...r,
        enabled: dbRuleStates[r.id] !== undefined ? dbRuleStates[r.id] : r.enabled
      }));

      const allRules = [...builtInWithStates, ...customRulesWithStates];
      setRules(allRules);

      localStorage.setItem('phpsentinel_custom_rules', JSON.stringify(customRulesWithStates));
      localStorage.setItem('phpsentinel_rule_states', JSON.stringify(mergedStates));
    } catch (error) {
      console.error('Failed to load rules:', error);
      const localStates = localStorage.getItem('phpsentinel_rule_states');
      if (localStates) {
        const ruleStates: Record<string, boolean> = JSON.parse(localStates);
        const builtInWithStates = BUILT_IN_RULES.map(r => ({
          ...r,
          enabled: ruleStates[r.id] !== undefined ? ruleStates[r.id] : r.enabled
        }));
        setRules(builtInWithStates);
      } else {
        setRules([...BUILT_IN_RULES]);
      }
    }
  };

  const filteredRules = useMemo(() => {
    return rules.filter(r => {
      const isWebshell = r.type === VulnerabilityType.WEBSHELL;
      return activeCategory === 'webshell' ? isWebshell : !isWebshell;
    });
  }, [rules, activeCategory]);

  const runTest = () => {
    if (!newRule.pattern) return;
    try {
      const regex = new RegExp(newRule.pattern, 'g');
      const matches: { match: string; line: number }[] = [];
      let m;
      while ((m = regex.exec(testCode)) !== null) {
        const line = testCode.substring(0, m.index).split('\n').length;
        matches.push({ match: m[0], line });
      }
      setTestResult(matches);
    } catch (e) {
      setTestResult([]);
    }
  };

  const saveToStorage = async (updatedRules: Rule[]) => {
    try {
      const ruleStates: Record<string, boolean> = {};
      updatedRules.forEach(r => {
        ruleStates[r.id] = r.enabled;
      });

      for (const [ruleId, enabled] of Object.entries(ruleStates)) {
        await rulesApi.saveState(ruleId, enabled);
      }

      const customRules = updatedRules.filter(r => !r.isBuiltIn);
      localStorage.setItem('phpsentinel_custom_rules', JSON.stringify(customRules));
      localStorage.setItem('phpsentinel_rule_states', JSON.stringify(ruleStates));

      setRules(updatedRules);
    } catch (error) {
      console.error('Failed to save rule states:', error);
    }
  };

  const toggleRule = (id: string) => {
    const updated = rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r);
    saveToStorage(updated);
  };

  const startEditRule = (rule: Rule) => {
    setEditingRuleId(rule.id);
    setEditForm({
      name: rule.name,
      pattern: rule.pattern,
      level: rule.level,
      type: rule.type,
      enabled: rule.enabled
    });
  };

  const cancelEdit = () => {
    setEditingRuleId(null);
    setEditForm({});
  };

  const saveEditRule = async (ruleId: string) => {
    if (!editForm.name || !editForm.pattern) return;
    
    try {
      const updatedRule: Rule = {
        ...editForm as Rule,
        id: ruleId,
        isBuiltIn: false
      };
      
      await rulesApi.update(ruleId, updatedRule);
      
      const updated = rules.map(r => r.id === ruleId ? updatedRule : r);
      setRules(updated);
      
      const customRules = updated.filter(r => !r.isBuiltIn);
      localStorage.setItem('phpsentinel_custom_rules', JSON.stringify(customRules));
      
      setEditingRuleId(null);
      setEditForm({});
    } catch (error) {
      console.error('Failed to update rule:', error);
      alert('更新规则失败');
    }
  };

  const addRule = async () => {
    if (!newRule.name || !newRule.pattern) return;
    const ruleType = activeCategory === 'webshell' ? VulnerabilityType.WEBSHELL : (newRule.type || VulnerabilityType.CUSTOM);
    const ruleToAdd: Rule = {
      ...newRule as Rule,
      id: 'c' + Math.random().toString(36).substr(2, 5),
      type: ruleType,
      isBuiltIn: false
    };

    try {
      await rulesApi.create(ruleToAdd);
      const updated = [...rules, ruleToAdd];
      setRules(updated);

      const customRules = updated.filter(r => !r.isBuiltIn);
      localStorage.setItem('phpsentinel_custom_rules', JSON.stringify(customRules));

      setNewRule({ name: '', pattern: '', level: RiskLevel.MEDIUM, type: VulnerabilityType.CUSTOM, enabled: true, isBuiltIn: false });
      setTestResult([]);
    } catch (error) {
      console.error('Failed to create rule:', error);
    }
  };

  const applyTemplate = (tpl: any) => {
    setNewRule({ ...newRule, name: tpl.name, pattern: tpl.pattern, type: tpl.type, level: tpl.level });
    if (tpl.type === VulnerabilityType.WEBSHELL) setActiveCategory('webshell');
    else setActiveCategory('general');
  };

  const deleteRule = async (id: string) => {
    try {
      await rulesApi.delete(id);
      const updated = rules.filter(r => r.id !== id);
      setRules(updated);

      const customRules = updated.filter(r => !r.isBuiltIn);
      localStorage.setItem('phpsentinel_custom_rules', JSON.stringify(customRules));
    } catch (error) {
      console.error('Failed to delete rule:', error);
    }
  };

  const handleExportRules = () => {
    const customRules = rules.filter(r => !r.isBuiltIn);
    if (customRules.length === 0) {
      alert('没有自定义规则可导出');
      return;
    }
    ExportService.exportRules(customRules);
  };

  const handleImportRules = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const importedRules = await ExportService.importRules(file);
      for (const rule of importedRules) {
        const newRule: Rule = {
          ...rule,
          id: 'c' + Math.random().toString(36).substr(2, 5),
          isBuiltIn: false,
          enabled: true,
        };
        await rulesApi.create(newRule);
      }
      await loadRules();
      alert(`成功导入 ${importedRules.length} 条规则`);
    } catch (error: any) {
      alert('导入失败: ' + error.message);
    } finally {
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const cardStyle = isDark ? 'bg-zinc-900 border-zinc-800' : 'bg-white border-zinc-200 shadow-sm';
  const inputStyle = isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-200' : 'bg-zinc-50 border-zinc-200 text-zinc-900';
  const isWebshellView = activeCategory === 'webshell';

  return (
    <div className="space-y-8 pb-20">
      
      {/* 顶部 Header: 标题与全局操作 */}
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-6 border-b pb-6 transition-colors duration-300" style={{ borderColor: isDark ? '#27272a' : '#e4e4e7' }}>
        <div className="flex flex-col gap-2">
          <h2 className={`text-4xl font-black tracking-tighter transition-colors ${isDark ? 'text-white' : 'text-zinc-900'}`}>
            规则工厂 <span className={isWebshellView ? 'text-rose-500' : (isDark ? 'text-emerald-500' : 'text-emerald-600')}>.</span>
          </h2>
          <p className="text-zinc-500 font-medium text-sm">定义 AST 引擎的匹配逻辑。内置库已涵盖 SQLi, XSS, RCE, 文件上传及 Webshell。</p>
        </div>

        <div className="flex items-center gap-3">
          <input type="file" ref={fileInputRef} onChange={handleImportRules} accept=".json" className="hidden" />
          <button onClick={() => fileInputRef.current?.click()} className={`px-4 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all border ${isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-emerald-400 hover:border-emerald-500/30' : 'bg-white border-zinc-200 text-zinc-600 hover:text-emerald-600 hover:border-emerald-300'}`}>
            导入规则
          </button>
          <button onClick={handleExportRules} className={`px-4 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all border ${isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-blue-400 hover:border-blue-500/30' : 'bg-white border-zinc-200 text-zinc-600 hover:text-blue-600 hover:border-blue-300'}`}>
            导出规则
          </button>
        </div>
      </header>

      {/* 核心布局: 左侧固定表单 + 右侧数据列表 */}
      <div className="flex flex-col xl:flex-row items-start gap-8">
        
        {/* 左侧栏: 吸顶 (Sticky) 操作区 */}
        <aside className="w-full xl:w-[420px] 2xl:w-[480px] shrink-0 flex flex-col gap-6 xl:sticky xl:top-6">
          
          {/* 配置表单 */}
          <div className={`border p-6 md:p-8 rounded-[32px] shadow-2xl space-y-6 transition-all ${cardStyle} ${isWebshellView ? 'border-rose-500/20 shadow-rose-500/5' : ''}`}>
            <div className="flex flex-col gap-3">
              <h3 className="text-lg font-bold flex items-center gap-2">
                <div className={`w-2.5 h-2.5 rounded-full ${isWebshellView ? 'bg-rose-500 shadow-[0_0_8px_#f43f5e]' : (isDark ? 'bg-emerald-500' : 'bg-emerald-600')}`}></div>
                配置{isWebshellView ? '木马特征' : '新型漏洞'}
              </h3>
              <div className="flex flex-wrap gap-2">
                 {RULE_TEMPLATES.filter(t => (activeCategory === 'webshell' ? t.type === VulnerabilityType.WEBSHELL : t.type !== VulnerabilityType.WEBSHELL)).slice(0, 3).map((t, idx) => (
                   <button key={idx} onClick={() => applyTemplate(t)} className={`px-2.5 py-1.5 text-[9px] font-black rounded border transition-colors ${isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-emerald-400' : 'bg-zinc-50 border-zinc-200 text-zinc-400 hover:text-emerald-600'}`}>
                     使用模板: {t.name.split(':')[0]}
                   </button>
                 ))}
              </div>
            </div>

            <div className="space-y-4">
              <div className="space-y-1">
                 <label className="text-[10px] font-bold text-zinc-500 uppercase">规则名称</label>
                 <input value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} placeholder="输入规则标识..." className={`w-full rounded-xl px-4 py-3 text-sm focus:border-emerald-500 outline-none transition-colors ${inputStyle}`} />
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                   <label className="text-[10px] font-bold text-zinc-500 uppercase">漏洞类型</label>
                   <select disabled={isWebshellView} value={isWebshellView ? VulnerabilityType.WEBSHELL : newRule.type} onChange={e => setNewRule({...newRule, type: e.target.value as VulnerabilityType})} className={`w-full rounded-xl px-4 py-3 text-sm transition-colors outline-none ${inputStyle}`}>
                     {Object.values(VulnerabilityType).map(t => <option key={t} value={t}>{t}</option>)}
                   </select>
                </div>
                <div className="space-y-1">
                   <label className="text-[10px] font-bold text-zinc-500 uppercase">风险等级</label>
                   <select value={newRule.level} onChange={e => setNewRule({...newRule, level: e.target.value as RiskLevel})} className={`w-full rounded-xl px-4 py-3 text-sm transition-colors outline-none ${inputStyle}`}>
                     {Object.values(RiskLevel).map(l => <option key={l} value={l}>{l}</option>)}
                   </select>
                </div>
              </div>

              <div className="space-y-1">
                 <label className="text-[10px] font-bold text-zinc-500 uppercase">正则表达式 (Regex Pattern)</label>
                 <textarea value={newRule.pattern} onChange={e => setNewRule({...newRule, pattern: e.target.value})} onBlur={runTest} placeholder="例如: (move_uploaded_file)\\(.*?(\\$.*?)\\)" className={`w-full rounded-xl px-4 py-3 text-sm font-mono focus:border-emerald-500 outline-none transition-colors resize-none h-20 ${isDark ? 'bg-zinc-950 border-zinc-800 text-emerald-400' : 'bg-zinc-50 border-zinc-200 text-emerald-700'} ${isWebshellView ? 'text-rose-400' : ''}`} />
              </div>
              
              <div className="pt-2">
                <button onClick={addRule} className={`w-full font-black py-3.5 rounded-xl text-sm transition-all shadow-lg active:scale-95 uppercase tracking-widest ${isWebshellView ? 'bg-rose-600 hover:bg-rose-500 text-white' : (isDark ? 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950' : 'bg-emerald-600 hover:bg-emerald-700 text-white')}`}>
                  部署规则
                </button>
              </div>
            </div>
          </div>

          {/* 实验室沙箱 */}
          <div className={`border p-6 md:p-8 rounded-[32px] shadow-2xl space-y-4 transition-all ${cardStyle}`}>
            <h3 className="text-lg font-bold flex items-center gap-2 text-zinc-500">实验室 (Playground)</h3>
            <div className="h-full flex flex-col">
               <textarea value={testCode} onChange={e => setTestCode(e.target.value)} onKeyUp={runTest} className={`flex-grow border rounded-2xl p-4 font-mono text-xs focus:outline-none min-h-[120px] transition-colors ${inputStyle}`} placeholder="输入 PHP 代码段进行匹配测试..." />
               <div className={`mt-4 p-4 rounded-xl border transition-colors ${isDark ? 'bg-black/40 border-zinc-800' : 'bg-zinc-100/50 border-zinc-200'}`}>
                  <p className="text-[10px] font-bold text-zinc-500 uppercase mb-2">匹配预览</p>
                  {testResult.length === 0 ? <p className="text-xs text-zinc-400 italic">尚未命中特征...</p> : (
                    <div className="space-y-2">
                      {testResult.map((res, i) => (
                        <div key={i} className="flex items-center justify-between text-[11px] font-mono">
                          <span className={`${isWebshellView ? 'text-rose-500' : (isDark ? 'text-emerald-500' : 'text-emerald-600')} truncate mr-2 font-bold`}>{res.match}</span>
                          <span className="text-zinc-400 shrink-0 uppercase text-[9px]">Line {res.line}</span>
                        </div>
                      ))}
                    </div>
                  )}
               </div>
            </div>
          </div>
        </aside>

        {/* 右侧主内容区: 规则列表与切换卡 */}
        <main className="flex-1 w-full space-y-6">
          
          {/* 分类切换栏 */}
          <div className={`p-1.5 rounded-2xl inline-flex items-center border transition-all ${isDark ? 'bg-zinc-950 border-zinc-900' : 'bg-zinc-100 border-zinc-200'}`}>
             <button onClick={() => setActiveCategory('general')} className={`px-8 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeCategory === 'general' ? (isDark ? 'bg-emerald-500 text-zinc-950' : 'bg-emerald-600 text-white shadow-lg') : 'text-zinc-500 hover:text-zinc-300'}`}>通用审计规则</button>
             <button onClick={() => setActiveCategory('webshell')} className={`px-8 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeCategory === 'webshell' ? 'bg-rose-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}>Webshell 特征库</button>
          </div>

          {/* 规则卡片 Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-6">
            {filteredRules.map(rule => {
              const isEditing = rule.id === editingRuleId;
              return (
                <div key={rule.id} className={`group p-6 rounded-[24px] border transition-all flex flex-col ${rule.enabled ? (isDark ? 'bg-zinc-900 border-zinc-800 shadow-xl' : 'bg-white border-zinc-200 shadow-md') : (isDark ? 'bg-zinc-950/50 border-zinc-900 opacity-60' : 'bg-zinc-50 border-zinc-100 opacity-60')} ${isWebshellView && rule.enabled ? (isDark ? 'border-rose-500/20' : 'border-rose-200 bg-rose-50/20') : ''} ${isEditing ? (isDark ? 'ring-2 ring-blue-500/30' : 'ring-2 ring-blue-400/30') : ''}`}>
                  {isEditing ? (
                    // 行内编辑模式
                    <div className="space-y-4 h-full flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-[10px] font-bold uppercase ${isDark ? 'text-blue-400' : 'text-blue-600'}`}>编辑模式</span>
                        <div className="flex items-center gap-2">
                          <button onClick={cancelEdit} className={`text-[10px] font-bold px-3 py-1.5 rounded-lg transition-colors ${isDark ? 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800' : 'text-zinc-500 hover:text-zinc-700 hover:bg-zinc-100'}`}>取消</button>
                          <button onClick={() => saveEditRule(rule.id)} className={`text-[10px] font-bold px-4 py-1.5 rounded-lg text-white transition-colors ${isWebshellView ? 'bg-rose-600 hover:bg-rose-500' : 'bg-emerald-600 hover:bg-emerald-500'}`}>保存</button>
                        </div>
                      </div>
                      <div className="space-y-3 flex-1">
                        <div className="space-y-1">
                          <input value={editForm.name || ''} onChange={e => setEditForm({...editForm, name: e.target.value})} className={`w-full rounded-lg px-3 py-2 text-sm outline-none transition-colors ${isDark ? 'bg-zinc-950 border border-zinc-800 text-zinc-200 focus:border-blue-500' : 'bg-white border border-zinc-200 text-zinc-900 focus:border-blue-500'}`} placeholder="规则名称" />
                        </div>
                        <div className="space-y-1 flex-1">
                          <textarea value={editForm.pattern || ''} onChange={e => setEditForm({...editForm, pattern: e.target.value})} className={`w-full rounded-lg px-3 py-2 text-xs font-mono outline-none transition-colors resize-none h-20 ${isDark ? 'bg-zinc-950 border border-zinc-800 text-emerald-400 focus:border-blue-500' : 'bg-white border border-zinc-200 text-emerald-700 focus:border-blue-500'}`} placeholder="正则表达式" />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <select value={editForm.type || VulnerabilityType.CUSTOM} onChange={e => setEditForm({...editForm, type: e.target.value as VulnerabilityType})} className={`w-full rounded-lg px-3 py-2 text-xs outline-none transition-colors ${isDark ? 'bg-zinc-950 border border-zinc-800 text-zinc-200' : 'bg-white border border-zinc-200 text-zinc-900'}`}>
                            {Object.values(VulnerabilityType).map(t => <option key={t} value={t}>{t}</option>)}
                          </select>
                          <select value={editForm.level || RiskLevel.MEDIUM} onChange={e => setEditForm({...editForm, level: e.target.value as RiskLevel})} className={`w-full rounded-lg px-3 py-2 text-xs outline-none transition-colors ${isDark ? 'bg-zinc-950 border border-zinc-800 text-zinc-200' : 'bg-white border border-zinc-200 text-zinc-900'}`}>
                            {Object.values(RiskLevel).map(l => <option key={l} value={l}>{l}</option>)}
                          </select>
                        </div>
                      </div>
                    </div>
                  ) : (
                    // 普通展示模式
                    <>
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-3">
                           <div className={`w-10 h-10 shrink-0 rounded-xl flex items-center justify-center border transition-colors ${rule.enabled ? (isWebshellView ? 'bg-rose-500/10 border-rose-500/20 text-rose-500' : (isDark ? 'bg-zinc-950 border-zinc-800 text-emerald-500' : 'bg-zinc-50 border-zinc-200 text-emerald-600')) : (isDark ? 'bg-zinc-900 border-zinc-800 text-zinc-700' : 'bg-zinc-100 border-zinc-200 text-zinc-400')}`}>
                             <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={isWebshellView ? "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" : "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944"} />
                             </svg>
                           </div>
                           <div className="min-w-0">
                              <h4 className={`font-bold text-sm truncate transition-colors ${isDark ? 'text-zinc-100' : 'text-zinc-900'}`} title={rule.name}>
                                {rule.name}
                                {rule.isBuiltIn && <span className={`text-[8px] font-normal border px-1 rounded ml-2 align-middle ${isDark ? 'text-zinc-600 border-zinc-800' : 'text-zinc-400 border-zinc-200'}`}>内置</span>}
                              </h4>
                              <div className="flex items-center gap-2 mt-1">
                                <p className={`text-[10px] font-mono ${isWebshellView ? 'text-rose-500/60' : 'text-zinc-500'}`}>{rule.type}</p>
                                <span className={`text-[8px] px-1.5 py-0.5 rounded-full uppercase ${rule.level === RiskLevel.CRITICAL ? 'bg-rose-500/10 text-rose-500' : rule.level === RiskLevel.HIGH ? 'bg-orange-500/10 text-orange-500' : 'bg-zinc-500/10 text-zinc-500'}`}>{rule.level}</span>
                              </div>
                           </div>
                        </div>
                      </div>
                      <div className={`mt-auto p-3 rounded-xl border transition-colors overflow-hidden ${isDark ? 'bg-black/40 border-zinc-800/50' : 'bg-zinc-50 border-zinc-100'}`}>
                         <code className={`text-[11px] font-mono break-all line-clamp-2 hover:line-clamp-none ${isWebshellView ? 'text-rose-400' : (isDark ? 'text-emerald-400' : 'text-emerald-700')}`} title={rule.pattern}>{rule.pattern}</code>
                      </div>
                      
                      {/* 底部操作栏 */}
                      <div className="flex items-center justify-between mt-4 pt-4 border-t" style={{ borderColor: isDark ? '#27272a' : '#f4f4f5' }}>
                        <button onClick={() => toggleRule(rule.id)} className={`px-3 py-1 rounded-full text-[9px] font-black uppercase transition-all ${rule.enabled ? (isWebshellView ? 'bg-rose-600 text-white shadow-md shadow-rose-500/20' : (isDark ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-emerald-50 text-emerald-600 border border-emerald-200')) : (isDark ? 'bg-zinc-800 text-zinc-500' : 'bg-zinc-100 text-zinc-400')}`}>
                          {rule.enabled ? '已激活' : '已停用'}
                        </button>
                        
                        {!rule.isBuiltIn && (
                          <div className="flex items-center gap-1">
                            <button onClick={() => startEditRule(rule)} className={`p-1.5 rounded-lg transition-colors ${isDark ? 'hover:bg-blue-500/10 text-zinc-600 hover:text-blue-400' : 'hover:bg-blue-50 text-zinc-400 hover:text-blue-600'}`} title="编辑规则">
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                            </button>
                            <button onClick={() => deleteRule(rule.id)} className={`p-1.5 rounded-lg transition-colors ${isDark ? 'hover:bg-rose-500/10 text-zinc-700 hover:text-rose-500' : 'hover:bg-rose-50 text-zinc-400 hover:text-rose-600'}`} title="删除规则">
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                            </button>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              );
            })}
          </div>
        </main>
      </div>
    </div>
  );
};

export default RuleConfig;