
import { useState, useEffect, useRef } from 'react';
import { Theme, ApiProviderConfig, ApiProfile } from '../types';
import { settingsApi } from '../frontend/src/api';
import { aiProxyApi } from '../frontend/src/api/ai-proxy';
import { ExportService } from '../services/exportService';

interface SettingsProps {
  theme: Theme;
}

const Settings: React.FC<SettingsProps> = ({ theme }) => {
  const isDark = theme === 'dark';
  const [config, setConfig] = useState<ApiProviderConfig>({
    activeProfileId: '',
    profiles: []
  });
  const [isEditing, setIsEditing] = useState<string | null>(null);
  const [testStatus, setTestStatus] = useState<{ id: string; msg: string; success?: boolean }>({ id: '', msg: '' });

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    // 优先从 localStorage 读取（GeminiService 也从此读取）
    const localConfig = localStorage.getItem('phpsentinel_ai_config');
    if (localConfig) {
      try {
        setConfig(JSON.parse(localConfig));
        return;
      } catch (e) {
        console.error('Failed to parse local config', e);
      }
    }
    
    // 如果 localStorage 没有，尝试从 API 加载
    try {
      const response = await settingsApi.get('ai_config');
      if (response.data && response.data.config) {
        setConfig(response.data.config);
        // 同步到 localStorage
        localStorage.setItem('phpsentinel_ai_config', JSON.stringify(response.data.config));
      }
    } catch (error) {
      console.error("Failed to load AI config", error);
    }
  };

  const saveConfig = async (newConfig: ApiProviderConfig) => {
    setConfig(newConfig);
    // 同时保存到 localStorage（供 GeminiService 读取）和 API
    localStorage.setItem('phpsentinel_ai_config', JSON.stringify(newConfig));
    try {
      await settingsApi.set('ai_config', newConfig);
    } catch (error) {
      console.error('Failed to save AI config to API:', error);
    }
  };

  const handleToggleProfile = (id: string) => {
    saveConfig({ ...config, activeProfileId: id });
  };

  const handleAddProfile = () => {
    const newId = 'profile-' + Math.random().toString(36).substr(2, 5);
    const newProfile: ApiProfile = {
      id: newId,
      name: '新配置',
      type: 'custom-openai',
      baseUrl: '',
      apiKey: '',
      modelName: 'gpt-4o'
    };
    saveConfig({ ...config, profiles: [...config.profiles, newProfile] });
    setIsEditing(newId);
  };

  const handleDeleteProfile = (id: string) => {
    const newProfiles = config.profiles.filter(p => p.id !== id);
    let newActiveId = config.activeProfileId;
    if (newActiveId === id) newActiveId = newProfiles.length > 0 ? newProfiles[0].id : '';
    saveConfig({ activeProfileId: newActiveId, profiles: newProfiles });
  };

  const updateProfile = (id: string, updates: Partial<ApiProfile>) => {
    const newProfiles = config.profiles.map(p => p.id === id ? { ...p, ...updates } : p);
    saveConfig({ ...config, profiles: newProfiles });
  };

  const handleTestApi = async (profile: ApiProfile) => {
    setTestStatus({ id: profile.id, msg: '正在测试连接...' });

    try {
      // 直接使用当前 profile 进行测试，不保存到数据库，不影响当前激活配置
      const response = await aiProxyApi.testConnectionWithProfile({
        id: profile.id,
        name: profile.name,
        type: profile.type,
        apiKey: profile.apiKey,
        baseUrl: profile.baseUrl,
        modelName: profile.modelName,
      });

      if (response.data?.status === 'success') {
        setTestStatus({ id: profile.id, msg: '连接成功！', success: true });
      } else {
        setTestStatus({ id: profile.id, msg: `失败: ${response.data?.message || '未知错误'}`, success: false });
      }
    } catch (error: any) {
      const errorMsg = error.response?.data?.detail || error.message || '连接失败';
      setTestStatus({ id: profile.id, msg: `错误: ${errorMsg}`, success: false });
    }
  };

  // 导出配置
  const handleExportConfig = () => {
    if (config.profiles.length === 0) {
      alert('没有配置可导出');
      return;
    }
    ExportService.exportConfig(config, 'AI-Config');
  };

  // 导入配置
  const fileInputRef = useRef<HTMLInputElement>(null);
  const handleImportConfig = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const { config: importedConfig } = await ExportService.importConfig(file);
      // 合并导入的配置（为每个 profile 生成新 ID）
      const newProfiles = importedConfig.profiles?.map((p: ApiProfile) => ({
        ...p,
        id: 'p' + Math.random().toString(36).substr(2, 9),
      })) || [];

      const mergedConfig: ApiProviderConfig = {
        activeProfileId: newProfiles[0]?.id || '',
        profiles: [...config.profiles, ...newProfiles],
      };

      await saveConfig(mergedConfig);
      alert(`成功导入 ${newProfiles.length} 个配置`);
    } catch (error: any) {
      alert('导入失败: ' + error.message);
    } finally {
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const cardStyle = isDark ? 'bg-zinc-900 border-zinc-800' : 'bg-white border-zinc-200 shadow-sm';
  const inputStyle = isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-100' : 'bg-zinc-50 border-zinc-200 text-zinc-900';

  return (
    <div className="space-y-10">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex flex-col gap-2">
          <h2 className={`text-4xl font-black tracking-tighter ${isDark ? 'text-white' : 'text-zinc-900'}`}>引擎设置</h2>
          <p className="text-zinc-500 font-medium text-sm">配置多模态审计引擎。支持兼容 OpenAI 协议的第三方 API（如 OpenAI、Moonshot、DeepSeek 等）。</p>
        </div>

        {/* 导入导出按钮 */}
        <div className="flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleImportConfig}
            accept=".json"
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className={`px-4 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all border ${
              isDark
                ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-emerald-400 hover:border-emerald-500/30'
                : 'bg-white border-zinc-200 text-zinc-600 hover:text-emerald-600 hover:border-emerald-300'
            }`}
          >
            导入配置
          </button>
          <button
            onClick={handleExportConfig}
            className={`px-4 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all border ${
              isDark
                ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-blue-400 hover:border-blue-500/30'
                : 'bg-white border-zinc-200 text-zinc-600 hover:text-blue-600 hover:border-blue-300'
            }`}
          >
            导出配置
          </button>
        </div>
      </div>

      <div className="space-y-6">
        {config.profiles.map(profile => (
          <div key={profile.id} className={`p-6 rounded-[32px] border transition-all ${cardStyle} ${config.activeProfileId === profile.id ? 'ring-2 ring-emerald-500/50 border-emerald-500/30 shadow-xl' : ''}`}>
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className={`w-12 h-12 rounded-2xl flex items-center justify-center bg-blue-500/10 text-blue-500`}>
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div>
                  <h3 className="font-bold text-lg">{profile.name}</h3>
                  <span className="text-[10px] font-black uppercase tracking-widest text-zinc-500">OpenAI Compatible API</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleToggleProfile(profile.id)}
                  className={`px-6 py-2 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all ${
                    config.activeProfileId === profile.id
                      ? 'bg-emerald-500 text-zinc-950'
                      : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  {config.activeProfileId === profile.id ? '已激活' : '设为默认'}
                </button>
                <button onClick={() => handleDeleteProfile(profile.id)} className="p-2 text-zinc-500 hover:text-rose-500 transition-colors">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                </button>
              </div>
            </div>

            <div className="mt-6 space-y-6 animate-in fade-in duration-300">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase ml-1">配置名称</label>
                  <input
                    value={profile.name}
                    onChange={e => updateProfile(profile.id, { name: e.target.value })}
                    placeholder="例如: Moonshot AI"
                    className={`w-full px-4 py-3 rounded-xl text-sm outline-none border transition-all ${inputStyle}`}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase ml-1">API Base URL</label>
                  <input
                    value={profile.baseUrl}
                    onChange={e => updateProfile(profile.id, { baseUrl: e.target.value })}
                    placeholder="https://api.openai.com/v1/chat/completions"
                    className={`w-full px-4 py-3 rounded-xl text-sm outline-none border transition-all ${inputStyle}`}
                  />
                  <p className="text-[9px] text-zinc-600 ml-1">请输入完整的 API 端点地址，系统将使用你提供的完整 URL 进行请求，不会添加任何后缀</p>
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase ml-1">API Key</label>
                  <input
                    type="password"
                    value={profile.apiKey}
                    onChange={e => updateProfile(profile.id, { apiKey: e.target.value })}
                    placeholder="sk-..."
                    className={`w-full px-4 py-3 rounded-xl text-sm outline-none border transition-all ${inputStyle}`}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase ml-1">模型名称 (Model Name)</label>
                  <input
                    value={profile.modelName}
                    onChange={e => updateProfile(profile.id, { modelName: e.target.value })}
                    placeholder="gpt-4o"
                    className={`w-full px-4 py-3 rounded-xl text-sm outline-none border transition-all ${inputStyle}`}
                  />
                </div>
              </div>
              <div className="flex items-center gap-4 pt-2">
                 <button 
                   onClick={() => handleTestApi(profile)}
                   className={`px-6 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${isDark ? 'border-zinc-800 hover:bg-zinc-800' : 'border-zinc-200 hover:bg-zinc-100'}`}
                 >
                   测试 API 连接
                 </button>
                 {testStatus.id === profile.id && (
                   <span className={`text-[10px] font-bold ${testStatus.success === true ? 'text-emerald-500' : testStatus.success === false ? 'text-rose-500' : 'text-zinc-500'}`}>
                      {testStatus.msg}
                   </span>
                 )}
              </div>
            </div>
          </div>
        ))}

        <button
          onClick={handleAddProfile}
          className="w-full py-6 rounded-[32px] border-2 border-dashed border-zinc-800 text-zinc-500 hover:text-emerald-500 hover:border-emerald-500/50 hover:bg-emerald-500/5 transition-all font-black uppercase tracking-widest text-xs"
        >
          + 添加自定义 AI 服务商 (OpenAI 协议)
        </button>
      </div>
    </div>
  );
};

export default Settings;
