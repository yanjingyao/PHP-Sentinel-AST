

import { Theme } from '../types';

interface LayoutProps {
  children: React.ReactNode;
  activeTab: string;
  onTabChange: (tab: string) => void;
  theme: Theme;
  onThemeToggle: () => void;
}

const Layout: React.FC<LayoutProps> = ({ children, activeTab, onTabChange, theme, onThemeToggle }) => {
  const isDark = theme === 'dark';

  const tabs = [
    { id: 'scan', label: '项目审计', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z' },
    { id: 'webshell', label: 'Webshell 猎手', icon: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5' },
    { id: 'network', label: '网络请求', icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9' },
    { id: 'rules', label: '规则工厂', icon: 'M9.37 5.51A7.35 7.35 0 009.1 7.12c0 4.46 4.77 1.54 4.77 6a5.13 5.13 0 01-5.13 5.13 5.12 5.12 0 01-5.12-5.13c0-4.46 4.77-1.54 4.77-6a7.05 7.05 0 00-.27-1.61L9.37 5.51zM12 2L4.5 20.29A2 2 0 006.33 23h11.34a2 2 0 001.83-2.71L12 2z' },
    { id: 'dashboard', label: '分析面板', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
    { id: 'history', label: '审计存档', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'settings', label: '引擎设置', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' }
  ];

  const getIconColor = (id: string, active: boolean) => {
    if (id === 'webshell' && active) return 'text-rose-500';
    if (active) return isDark ? 'text-emerald-400' : 'text-emerald-600';
    return isDark ? 'text-zinc-600 hover:text-zinc-300' : 'text-zinc-400 hover:text-zinc-600';
  };

  return (
    <div className={`h-screen w-screen flex transition-colors duration-300 overflow-hidden ${
      isDark ? 'bg-zinc-950 text-zinc-300' : 'bg-zinc-50 text-zinc-700'
    }`}>
      <aside className={`w-14 flex flex-col items-center py-4 gap-4 border-r shrink-0 transition-colors duration-300 ${
        isDark ? 'border-zinc-900 bg-zinc-950' : 'border-zinc-200 bg-zinc-100'
      }`}>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-4 shadow-lg transition-all ${
          isDark ? 'bg-emerald-500 shadow-emerald-500/20' : 'bg-emerald-600 shadow-emerald-600/20'
        }`}>
          <svg className={`w-5 h-5 ${isDark ? 'text-zinc-950' : 'text-white'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        
        <div className="flex-grow flex flex-col gap-2">
          {tabs.map(tab => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                title={tab.label}
                className={`w-14 h-12 flex items-center justify-center transition-all relative group ${getIconColor(tab.id, isActive)}`}
              >
                {isActive && (
                  <div className={`absolute left-0 w-[2.5px] h-6 transition-colors ${
                    tab.id === 'webshell' ? 'bg-rose-500' : (isDark ? 'bg-emerald-500' : 'bg-emerald-600')
                  }`}></div>
                )}
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={tab.icon} />
                </svg>
              </button>
            );
          })}
        </div>

        <button
          onClick={onThemeToggle}
          className={`w-10 h-10 rounded-full flex items-center justify-center transition-all ${
            isDark ? 'text-zinc-600 hover:text-amber-400 hover:bg-zinc-900' : 'text-zinc-400 hover:text-amber-600 hover:bg-zinc-200'
          }`}
        >
          {isDark ? (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707M16.243 16.243l.707.707M7.757 7.757l.707-.707M12 8a4 4 0 100 8 4 4 0 000-8z" /></svg>
          ) : (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
          )}
        </button>
      </aside>

      <main className="flex-grow flex flex-col relative overflow-hidden">
        {children}
      </main>
    </div>
  );
};

export default Layout;
