
import { useState, useRef, useEffect, useCallback } from 'react';
import Editor, { OnMount } from '@monaco-editor/react';
import { NetworkLog, Theme } from '../types';
import { networkApi } from '../frontend/src/api';

interface NetworkLabProps {
  theme: Theme;
}

const NetworkLab: React.FC<NetworkLabProps> = ({ theme }) => {
  const isDark = theme === 'dark';
  
  // Repeater State
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://jsonplaceholder.typicode.com/posts/1');
  
  // Unified Request Content (Headers + \n\n + Body)
  const [reqContent, setReqContent] = useState(
    'User-Agent: PHP-Sentinel/1.0\nAccept: application/json\nContent-Type: application/json\n\n{\n  "title": "foo",\n  "body": "bar",\n  "userId": 1\n}'
  );
  
  const [isLoading, setIsLoading] = useState(false);
  
  // Unified Response Content
  const [resContent, setResContent] = useState('');
  
  // Response Meta for status bar
  const [resMeta, setResMeta] = useState<{status: number, statusText: string, time: number, size: number} | null>(null);

  // History State
  const [history, setHistory] = useState<NetworkLog[]>([]);
  const [historyHeight, setHistoryHeight] = useState(240); // 默认高度
  const isResizing = useRef(false);

  // Load history from API on mount
  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      const response = await networkApi.getAll(50);
      const logs: NetworkLog[] = response.data.map((entry: any) => ({
        id: entry.id,
        timestamp: new Date(entry.created_at).getTime(),
        method: entry.method,
        url: entry.url,
        requestHeaders: entry.request_headers,
        requestBody: entry.request_body,
        responseStatus: entry.response_status,
        responseStatusText: entry.response_status_text,
        responseHeaders: entry.response_headers,
        responseBody: entry.response_body,
        duration: entry.duration,
        size: entry.size
      }));
      setHistory(logs);
    } catch (error) {
      console.error('Failed to load network history:', error);
    }
  };

  // Resizing Logic for History Panel
  const startResizing = useCallback(() => {
    isResizing.current = true;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
  }, []);

  const stopResizing = useCallback(() => {
    isResizing.current = false;
    document.body.style.cursor = 'default';
    document.body.style.userSelect = 'auto';
  }, []);

  const handleResize = useCallback((e: MouseEvent) => {
    if (!isResizing.current) return;
    const newHeight = window.innerHeight - e.clientY;
    // 限制高度范围：最小 100px，最大为窗口高度的 80%
    if (newHeight > 100 && newHeight < window.innerHeight * 0.8) {
      setHistoryHeight(newHeight);
    }
  }, []);

  useEffect(() => {
    window.addEventListener('mousemove', handleResize);
    window.addEventListener('mouseup', stopResizing);
    return () => {
      window.removeEventListener('mousemove', handleResize);
      window.removeEventListener('mouseup', stopResizing);
    };
  }, [handleResize, stopResizing]);

  // Request Parser for Paste Event and Content Change
  const handleEditorDidMount: OnMount = (editor, monaco) => {
    // Handle Paste
    editor.onDidPaste(() => {
      setTimeout(() => {
        const content = editor.getValue();
        parseRawRequest(content);
      }, 50);
    });

    // Handle Content Change (Real-time sync)
    // Using a debounce to avoid excessive updates
    let debounceTimer: NodeJS.Timeout;
    editor.onDidChangeModelContent(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const content = editor.getValue();
        parseRawRequest(content);
      }, 500); // 500ms debounce
    });
  };

  const parseRawRequest = (content: string) => {
    try {
      const lines = content.split(/\r?\n/);
      if (lines.length === 0) return;

      // Parse Request Line: METHOD PATH HTTP/VERSION
      // Example: POST /vul/unserilization/unser.php HTTP/1.1
      const requestLineRegex = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d\.\d/i;
      const match = lines[0].match(requestLineRegex);

      if (match) {
        const newMethod = match[1].toUpperCase();
        let path = match[2];
        let newUrl = '';

        // Find Host, Origin, Referer headers
        let host = '';
        let origin = '';
        let referer = '';

        for (const line of lines) {
          const hostMatch = line.match(/^Host:\s*([^\s]+)/i);
          if (hostMatch) host = hostMatch[1].trim();

          const originMatch = line.match(/^Origin:\s*([^\s]+)/i);
          if (originMatch) origin = originMatch[1].trim();

          const refererMatch = line.match(/^Referer:\s*([^\s]+)/i);
          if (refererMatch) referer = refererMatch[1].trim();
        }

        if (path.startsWith('http://') || path.startsWith('https://')) {
          newUrl = path;
        } else if (host) {
          // Construct URL
          let protocol = 'http://';
          
          // 1. Port-based inference
          if (host.endsWith(':443') || host.endsWith(':8443')) {
            protocol = 'https://';
          } 
          // 2. Origin/Referer-based inference
          else if (origin && origin.startsWith('https://')) {
            protocol = 'https://';
          }
          else if (referer && referer.startsWith('https://')) {
            protocol = 'https://';
          }
          // 3. Sticky Protocol (Use existing URL protocol if host matches)
          else {
            try {
              // Extract current protocol if url is valid
              if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                const currentUrlObj = new URL(url);
                // Check if host matches (ignoring port if standard)
                const currentHost = currentUrlObj.host;
                const targetHost = host;
                
                // Simple host match or match with default ports
                if (currentHost === targetHost || 
                    currentHost === targetHost + ':80' || 
                    currentHost === targetHost + ':443' ||
                    targetHost === currentHost + ':80' ||
                    targetHost === currentHost + ':443') {
                  protocol = currentUrlObj.protocol + '//';
                }
              }
            } catch (e) {
              // Ignore URL parsing errors
            }
          }

          // Ensure path starts with /
          if (!path.startsWith('/')) path = '/' + path;
          newUrl = `${protocol}${host}${path}`;
        }

        // Only update if changed to avoid cursor jumping or loops
        if (newUrl && (newUrl !== url || newMethod !== method)) {
          setMethod(newMethod);
          setUrl(newUrl);
          // console.log('[Auto-Detect] Updated request from raw content:', newMethod, newUrl);
        }
      }
    } catch (e) {
      console.error('Failed to parse raw request:', e);
    }
  };

  const saveHistory = async (newLog: NetworkLog) => {
    try {
      await networkApi.create(newLog);
      // 重新加载历史记录
      await loadHistory();
    } catch (error) {
      console.error('Failed to save network log:', error);
    }
  };

  const deleteLog = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await networkApi.delete(id);
      const updated = history.filter(h => h.id !== id);
      setHistory(updated);
    } catch (error) {
      console.error('Failed to delete network log:', error);
    }
  };

  const clearHistory = async () => {
    if (history.length === 0) return;
    if (window.confirm('确定要清空所有网络请求历史记录吗？')) {
      try {
        await networkApi.clearAll();
        setHistory([]);
      } catch (error) {
        console.error('Failed to clear network history:', error);
      }
    }
  };

  const executeRequest = async () => {
    if (!url) return;
    setIsLoading(true);
    const startTime = performance.now();
    
    try {
      // Split Headers and Body
      // Normalize line endings to \n and find double newline
      const normalizedReq = reqContent.replace(/\r\n/g, '\n');
      const splitIndex = normalizedReq.indexOf('\n\n');
      
      let headerText = normalizedReq;
      let bodyText = '';
      
      if (splitIndex !== -1) {
        headerText = normalizedReq.substring(0, splitIndex);
        bodyText = normalizedReq.substring(splitIndex + 2);
      }

      // Parse Headers
      const headerObj: Record<string, string> = {};
      headerText.split('\n').forEach(line => {
        // Skip empty lines and request line (e.g., "GET /path HTTP/1.1")
        if (!line.trim()) return;
        if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/i.test(line)) return;
        
        const parts = line.split(':');
        if (parts.length >= 2) {
          const key = parts[0].trim();
          const val = parts.slice(1).join(':').trim();
          if (key) headerObj[key] = val;
        }
      });

      // Use backend proxy to bypass CORS and access internal network
      try {
        const response = await networkApi.proxy({
          method,
          url,
          headers: headerObj,
          body: (method !== 'GET' && method !== 'HEAD') ? bodyText : undefined,
          timeout: 30
        });

        const data = response.data;

        // Format Response
        let resHeaderStr = '';
        if (data.headers) {
          Object.entries(data.headers).forEach(([key, val]) => {
            resHeaderStr += `${key}: ${val}\n`;
          });
        }
        
        const fullResponse = `HTTP/1.1 ${data.status} ${data.status_text}\n${resHeaderStr}\n${data.body}`;

        setResMeta({
          status: data.status,
          statusText: data.status_text,
          time: data.time,
          size: data.size
        });
        setResContent(fullResponse);

        // Log to History
        const log: NetworkLog = {
          id: Math.random().toString(36).substr(2, 9),
          timestamp: Date.now(),
          method,
          url,
          requestHeaders: headerText,
          requestBody: bodyText,
          responseStatus: data.status,
          responseStatusText: data.status_text,
          responseHeaders: resHeaderStr,
          responseBody: data.body,
          duration: data.time,
          size: data.size
        };
        saveHistory(log);
      } catch (error: any) {
        console.error('Proxy request failed:', error);
        const errorMsg = error.response?.data?.detail || error.message || 'Unknown Error';
        setResMeta({ status: 0, statusText: 'Error', time: 0, size: 0 });
        setResContent(`Error: ${errorMsg}\n\n[调试建议]\n1. 检查目标 URL 是否正确且可访问。\n2. 请求已通过后端代理转发，支持访问内网 (127.0.0.1)。\n3. 如果是 HTTPS 请求，请确保后端能够信任或忽略证书错误。`);
      }
    } catch (error: any) {
      setResMeta({ status: 0, statusText: 'Error', time: 0, size: 0 });
      setResContent(`Error: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Keyboard shortcut for URL input
  const handleUrlKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      executeRequest();
    }
  };

  // Utility: Format JSON Body in Request
  const formatRequestBody = () => {
    const normalizedReq = reqContent.replace(/\r\n/g, '\n');
    const splitIndex = normalizedReq.indexOf('\n\n');
    
    if (splitIndex !== -1) {
      const header = normalizedReq.substring(0, splitIndex);
      const body = normalizedReq.substring(splitIndex + 2);
      try {
        const json = JSON.parse(body);
        const formatted = JSON.stringify(json, null, 2);
        setReqContent(`${header}\n\n${formatted}`);
      } catch (e) {
        alert('Request body is not valid JSON.');
      }
    }
  };

  // Utility: Copy Response to Clipboard
  const copyResponse = () => {
    if (!resContent) return;
    navigator.clipboard.writeText(resContent);
    // Optional: Could show a toast here
  };

  const loadFromHistory = (log: NetworkLog) => {
    setMethod(log.method);
    setUrl(log.url);
    // Combine headers and body for display
    setReqContent(`${log.requestHeaders}\n\n${log.requestBody}`);
    
    const fullRes = `HTTP/1.1 ${log.responseStatus} ${log.responseStatusText}\n${log.responseHeaders}\n${log.responseBody}`;
    setResContent(fullRes);
    
    setResMeta({
      status: log.responseStatus,
      statusText: log.responseStatusText,
      time: log.duration,
      size: log.size
    });
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-emerald-500';
    if (status >= 300 && status < 400) return 'text-amber-500';
    return 'text-rose-500';
  };

  const inputStyle = isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-200' : 'bg-zinc-50 border-zinc-200 text-zinc-900';
  const sectionHeaderStyle = isDark ? 'bg-zinc-900/50 border-zinc-900 text-zinc-500' : 'bg-zinc-50 border-zinc-200 text-zinc-500';

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Top Bar: Request Composer */}
      <div className={`h-16 shrink-0 flex items-center px-4 gap-4 border-b ${isDark ? 'bg-zinc-950 border-zinc-900' : 'bg-white border-zinc-200'}`}>
        <select 
          value={method} 
          onChange={e => setMethod(e.target.value)}
          className={`h-9 px-3 rounded-lg font-bold text-xs uppercase outline-none border transition-colors ${inputStyle}`}
        >
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <input 
          type="text" 
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={handleUrlKeyDown}
          placeholder="Enter Target URL (e.g. http://localhost:8000/api/login)"
          className={`flex-grow h-9 px-4 rounded-lg font-mono text-sm outline-none border transition-colors ${inputStyle}`}
        />

        <button 
          onClick={executeRequest}
          disabled={isLoading}
          className={`h-9 px-6 rounded-lg text-xs font-black uppercase tracking-widest transition-all shadow-lg active:scale-95 flex items-center gap-2 ${
            isLoading 
              ? 'bg-zinc-700 text-zinc-400 cursor-not-allowed'
              : (isDark ? 'bg-orange-600 text-white hover:bg-orange-500' : 'bg-orange-500 text-white hover:bg-orange-600')
          }`}
        >
          {isLoading ? (
             <div className="w-4 h-4 border-2 border-zinc-400 border-t-transparent rounded-full animate-spin"></div>
          ) : 'Send'}
        </button>
      </div>

      {/* Main Area: Split Pane */}
      <div className="flex-grow flex overflow-hidden">
        {/* Left: Request Pane (Combined) */}
        <div className={`w-1/2 flex flex-col border-r ${isDark ? 'border-zinc-900' : 'border-zinc-200'}`}>
           <div className={`h-8 flex items-center justify-between px-4 shrink-0 border-b ${sectionHeaderStyle}`}>
              <span className="text-[10px] font-black uppercase tracking-widest">Request (Raw)</span>
              <button 
                onClick={formatRequestBody}
                className="text-[9px] font-bold uppercase hover:text-emerald-500 transition-colors flex items-center gap-1"
                title="Format JSON Body"
              >
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16m-7 6h7" /></svg>
                Beautify JSON
              </button>
           </div>
           <div className="flex-grow relative">
              <Editor 
                height="100%" 
                theme={isDark ? 'vs-dark' : 'light'} 
                language="http" // http provides decent highlighting for headers
                value={reqContent} 
                onChange={(val) => setReqContent(val || '')}
                onMount={handleEditorDidMount}
                options={{ 
                  minimap: { enabled: false }, 
                  fontSize: 13, 
                  scrollBeyondLastLine: false, 
                  wordWrap: 'on', 
                  automaticLayout: true,
                  renderLineHighlight: 'none'
                }} 
              />
           </div>
        </div>

        {/* Right: Response Pane (Combined) */}
        <div className="w-1/2 flex flex-col">
           <div className={`h-8 flex items-center justify-between px-4 shrink-0 border-b ${sectionHeaderStyle}`}>
              <div className="flex items-center gap-4">
                <span className="text-[10px] font-black uppercase tracking-widest">Response (Raw)</span>
                {resContent && (
                  <button 
                    onClick={copyResponse}
                    className="text-[9px] font-bold uppercase hover:text-emerald-500 transition-colors flex items-center gap-1"
                    title="Copy full response"
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
                    Copy
                  </button>
                )}
              </div>
              <div className="flex items-center gap-3 text-[10px] font-mono">
                 {resMeta && (
                   <>
                     <span className={`font-black ${getStatusColor(resMeta.status)}`}>{resMeta.status} {resMeta.statusText}</span>
                     <span className={isDark ? "text-zinc-500" : "text-zinc-400"}>{resMeta.time}ms</span>
                     <span className={isDark ? "text-zinc-500" : "text-zinc-400"}>{(resMeta.size / 1024).toFixed(2)}KB</span>
                   </>
                 )}
              </div>
           </div>
           <div className={`flex-grow relative ${isDark ? 'bg-zinc-950' : 'bg-white'}`}>
              <Editor 
                height="100%" 
                theme={isDark ? 'vs-dark' : 'light'} 
                language="http" 
                value={resContent} 
                options={{ 
                  minimap: { enabled: false }, 
                  fontSize: 13, 
                  readOnly: true, 
                  scrollBeyondLastLine: false, 
                  wordWrap: 'on', 
                  automaticLayout: true,
                  renderLineHighlight: 'none'
                }} 
              />
           </div>
        </div>
      </div>

      {/* Bottom: Proxy History (Resizable) */}
      <div 
        style={{ height: historyHeight }} 
        className={`shrink-0 border-t flex flex-col relative transition-colors ${isDark ? 'bg-zinc-950 border-zinc-900' : 'bg-white border-zinc-200'}`}
      >
        {/* Resize Handle */}
        <div 
          onMouseDown={startResizing}
          className={`absolute top-0 left-0 right-0 h-[5px] cursor-row-resize z-50 transition-colors ${isDark ? 'hover:bg-emerald-500/50' : 'hover:bg-emerald-500/30'}`}
        />
        
        <div className={`h-8 px-4 flex items-center border-b justify-between shrink-0 ${isDark ? 'bg-zinc-900/30 border-zinc-900' : 'bg-zinc-50 border-zinc-200'}`}>
           <span className="text-[10px] font-black uppercase text-zinc-500 tracking-widest">HTTP Proxy History</span>
           <button onClick={clearHistory} className="text-[10px] text-zinc-500 hover:text-rose-500">CLEAR HISTORY</button>
        </div>
        <div className="flex-grow overflow-y-auto custom-scrollbar">
           <table className="w-full text-left border-collapse">
              <thead className={`sticky top-0 text-[10px] font-bold uppercase ${isDark ? 'bg-zinc-950 text-zinc-500' : 'bg-white text-zinc-400'}`}>
                 <tr>
                    <th className="px-4 py-2 w-16">#</th>
                    <th className="px-4 py-2 w-20">Method</th>
                    <th className="px-4 py-2">URL</th>
                    <th className="px-4 py-2 w-20">Status</th>
                    <th className="px-4 py-2 w-20">Size</th>
                    <th className="px-4 py-2 w-20">Time</th>
                    <th className="px-4 py-2 w-32 text-right">Time</th>
                    <th className="px-4 py-2 w-10"></th>
                 </tr>
              </thead>
              <tbody className="font-mono text-[11px]">
                 {history.map((log, idx) => (
                    <tr 
                      key={log.id} 
                      onClick={() => loadFromHistory(log)}
                      className={`cursor-pointer border-b transition-colors group ${
                        isDark 
                          ? 'border-zinc-900 hover:bg-zinc-900 text-zinc-400' 
                          : 'border-zinc-100 hover:bg-zinc-50 text-zinc-700'
                      }`}
                    >
                       <td className="px-4 py-1.5 opacity-50">{history.length - idx}</td>
                       <td className={`px-4 py-1.5 font-bold ${log.method === 'POST' ? 'text-orange-500' : (log.method === 'DELETE' ? 'text-rose-500' : 'text-blue-500')}`}>{log.method}</td>
                       <td className="px-4 py-1.5 truncate max-w-[300px]" title={log.url}>{log.url}</td>
                       <td className={`px-4 py-1.5 font-bold ${getStatusColor(log.responseStatus)}`}>{log.responseStatus}</td>
                       <td className="px-4 py-1.5">{log.size}</td>
                       <td className="px-4 py-1.5">{log.duration}ms</td>
                       <td className="px-4 py-1.5 text-right opacity-50">{new Date(log.timestamp).toLocaleTimeString()}</td>
                       <td className="px-4 py-1.5 text-center">
                          <button 
                            onClick={(e) => deleteLog(e, log.id)}
                            className={`opacity-0 group-hover:opacity-100 p-1 rounded transition-all ${
                                isDark ? 'hover:bg-zinc-800 hover:text-rose-500 text-zinc-600' : 'hover:bg-zinc-200 hover:text-rose-600 text-zinc-400'
                            }`}
                            title="Remove log"
                          >
                             <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                          </button>
                       </td>
                    </tr>
                 ))}
                 {history.length === 0 && (
                   <tr>
                     <td colSpan={8} className="px-4 py-8 text-center text-zinc-500 italic text-xs">No requests captured yet. Use the Repeater above to generate traffic.</td>
                   </tr>
                 )}
              </tbody>
           </table>
        </div>
      </div>
    </div>
  );
};

export default NetworkLab;
