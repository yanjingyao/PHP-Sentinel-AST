
import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import Editor, { OnMount, loader } from '@monaco-editor/react';
import Layout from './components/Layout';
import VulnerabilityItem from './components/VulnerabilityItem';
import Dashboard from './components/Dashboard';
import Home from './components/Home';
import Settings from './components/Settings';
import RuleConfig from './components/RuleConfig';
import NetworkLab from './components/NetworkLab';
import VulnerabilityCard from './components/VulnerabilityCard';
import { dbService } from './services/dbService';
import { AIService } from './services/aiService';
import { projectApi, scanApi, vulnerabilityApi } from './frontend/src/api';
import { ScanResult, Vulnerability, RiskLevel, FileData, Theme } from './types';
import JSZip from 'jszip';

// 配置 Monaco Editor 的 CDN 资源地址
const MONACO_VERSION = '0.45.0';
const MONACO_CDN_BASE = `https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/${MONACO_VERSION}/min/vs`;

loader.config({
  paths: { vs: MONACO_CDN_BASE }
});

if (typeof window !== 'undefined') {
  (window as any).MonacoEnvironment = {
    getWorkerUrl: function (_moduleId: any, label: string) {
      let workerUrl = `${MONACO_CDN_BASE}/base/worker/workerMain.js`;
      if (label === 'json') workerUrl = `${MONACO_CDN_BASE}/language/json/json.worker.js`;
      if (label === 'css' || label === 'scss' || label === 'less') workerUrl = `${MONACO_CDN_BASE}/language/css/css.worker.js`;
      if (label === 'html' || label === 'handlebars' || label === 'razor') workerUrl = `${MONACO_CDN_BASE}/language/html/html.worker.js`;
      if (label === 'typescript' || label === 'javascript') workerUrl = `${MONACO_CDN_BASE}/language/typescript/ts.worker.js`;

      const code = `
        self.MonacoEnvironment = { baseUrl: '${MONACO_CDN_BASE.replace('/vs', '')}' };
        importScripts('${workerUrl}');
      `;
      return `data:text/javascript;charset=utf-8,${encodeURIComponent(code)}`;
    }
  };
}

const normalizePath = (path: string) => path?.replace(/\\/g, '/') || '';
const getBasename = (path: string) => normalizePath(path).split('/').pop() || path;

interface FileNode {
  name: string;
  path: string;
  children?: FileNode[];
  fileIndex?: number;
}

interface ProjectState {
  files: FileData[];
  projectName: string;
  scanResult: ScanResult | null;
  openFileIndices: number[];
  activeTabIndex: number;
  expandedFolders: Set<string>;
  selectedVulnId: string | null;
  batchSelectedIds: Set<string>;
  modifiedFiles: Set<number>; // 跟踪已修改但未保存的文件索引
}

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState('home');
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('phpsentinel_theme') as Theme) || 'dark');
  
  const [leftWidth, setLeftWidth] = useState(260);
  const [rightWidth, setRightWidth] = useState(340);
  const [detailWidth, setDetailWidth] = useState(600);
  const isResizing = useRef<'left' | 'right' | 'detail' | null>(null);

  const [auditState, setAuditState] = useState<ProjectState>({
    files: [{
      name: 'src/Auth/Authenticator.php',
      content: '<?php\nnamespace App\\Auth;\n\nclass Authenticator {\n    public function login($user, $pass) {\n        $sql = "SELECT * FROM users WHERE name = \'$user\' AND password = \'$pass\'";\n        return $this->db->query($sql);\n    }\n}'
    }],
    projectName: 'PHP-SENTINEL-WORKSPACE',
    scanResult: null,
    openFileIndices: [0],
    activeTabIndex: 0,
    expandedFolders: new Set(['src']),
    selectedVulnId: null,
    batchSelectedIds: new Set<string>(),
    modifiedFiles: new Set<number>()
  });

  const [webshellState, setWebshellState] = useState<ProjectState>({
    files: [],
    projectName: 'WEBSHELL-HUNTER-TARGET',
    scanResult: null,
    openFileIndices: [],
    activeTabIndex: -1,
    expandedFolders: new Set<string>(),
    selectedVulnId: null,
    batchSelectedIds: new Set<string>(),
    modifiedFiles: new Set<number>()
  });

  const [allScans, setAllScans] = useState<ScanResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [autoScanEnabled, setAutoScanEnabled] = useState(false);
  
  const [isBatchAnalyzing, setIsBatchAnalyzing] = useState(false);
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 });
  const [batchTimeEstimate, setBatchTimeEstimate] = useState<number | null>(null);
  const [batchStartTime, setBatchStartTime] = useState<number | null>(null);
  const [batchRemainingTime, setBatchRemainingTime] = useState<number | null>(null);
  const shouldStopBatchRef = useRef(false); // 用于停止批量审计的标记
  const [reviewingVulnIds, setReviewingVulnIds] = useState<Set<string>>(new Set());

  // 批量审计剩余时间定时更新
  useEffect(() => {
    if (!isBatchAnalyzing || !batchTimeEstimate || !batchStartTime) {
      setBatchRemainingTime(null);
      return;
    }
    const interval = setInterval(() => {
      const elapsed = (Date.now() - batchStartTime) / 1000;
      const remaining = Math.max(0, Math.ceil(batchTimeEstimate - elapsed));
      setBatchRemainingTime(remaining);
    }, 1000);
    return () => clearInterval(interval);
  }, [isBatchAnalyzing, batchTimeEstimate, batchStartTime]);

  // 筛选和搜索状态
  const [vulnSearchQuery, setVulnSearchQuery] = useState('');
  const [vulnFilterLevel, setVulnFilterLevel] = useState<RiskLevel | 'all'>('all');
  const [vulnFilterType, setVulnFilterType] = useState<string>('all');
  const [vulnFilterAuditStatus, setVulnFilterAuditStatus] = useState<'all' | 'audited' | 'unaudited'>('all');
  const [vulnFilterPhpOnly, setVulnFilterPhpOnly] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);
  const editorRef = useRef<any>(null);
  const monacoRef = useRef<any>(null);
  const decorationsRef = useRef<string[]>([]);
  const fileTreeRef = useRef<HTMLDivElement>(null);

  const isDark = theme === 'dark';
  const isWebshellView = activeTab === 'webshell';
  const isScanOrWebshell = activeTab === 'scan' || activeTab === 'webshell';

  const handleResize = useCallback((e: MouseEvent) => {
    if (!isResizing.current) return;
    if (isResizing.current === 'left') {
      const newWidth = e.clientX - 56;
      if (newWidth >= 180 && newWidth <= 600) setLeftWidth(newWidth);
    } else if (isResizing.current === 'right') {
      const newWidth = window.innerWidth - e.clientX;
      if (newWidth >= 250 && newWidth <= 800) setRightWidth(newWidth);
    } else if (isResizing.current === 'detail') {
      const newWidth = window.innerWidth - e.clientX;
      if (newWidth >= 400 && newWidth <= window.innerWidth * 0.8) setDetailWidth(newWidth);
    }
  }, []);

  useEffect(() => {
    window.addEventListener('mousemove', handleResize);
    window.addEventListener('mouseup', () => { isResizing.current = null; document.body.style.cursor = 'default'; });
    return () => window.removeEventListener('mousemove', handleResize);
  }, [handleResize]);

  const currentProject = isWebshellView ? webshellState : auditState;
  
  const updateProject = (updates: Partial<ProjectState>) => {
    if (isWebshellView) setWebshellState(prev => ({ ...prev, ...updates }));
    else setAuditState(prev => ({ ...prev, ...updates }));
  };

  // 同步扫描状态到数据库（仅更新漏洞AI评估，不创建新扫描记录）
  const syncScanToDb = async (updatedScan: ScanResult) => {
    updateProject({ scanResult: updatedScan });
    // AI审计结果已通过/api/ai/review接口自动保存
    // 此处只需刷新历史记录以同步状态
    await loadHistory();
  };

  const currentFileIndex = currentProject.openFileIndices[currentProject.activeTabIndex] ?? -1;

  // 获取所有唯一的漏洞类型
  const uniqueVulnTypes = useMemo(() => {
    const types = new Set<string>();
    currentProject.scanResult?.vulnerabilities?.forEach(v => {
      if (v.type) types.add(v.type);
    });
    return Array.from(types).sort();
  }, [currentProject.scanResult]);

  // 统计各等级数量
  const vulnStats = useMemo(() => {
    const stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, audited: 0 };
    const vulns = currentProject.scanResult?.vulnerabilities || [];
    stats.total = vulns.length;
    vulns.forEach(v => {
      if (v.level === RiskLevel.CRITICAL) stats.critical++;
      if (v.level === RiskLevel.HIGH) stats.high++;
      if (v.level === RiskLevel.MEDIUM) stats.medium++;
      if (v.level === RiskLevel.LOW) stats.low++;
      if (v.aiAssessment) stats.audited++;
    });
    return stats;
  }, [currentProject.scanResult]);

  // 带筛选的漏洞列表
  const displayedVulns = useMemo(() => {
    let vulns = currentProject.scanResult?.vulnerabilities || [];

    // 1. 搜索过滤
    if (vulnSearchQuery.trim()) {
      const query = vulnSearchQuery.toLowerCase();
      vulns = vulns.filter(v =>
        v.fileName?.toLowerCase().includes(query) ||
        v.type?.toLowerCase().includes(query) ||
        v.description?.toLowerCase().includes(query)
      );
    }

    // 2. 风险等级筛选
    if (vulnFilterLevel !== 'all') {
      vulns = vulns.filter(v => v.level === vulnFilterLevel);
    }

    // 3. 漏洞类型筛选
    if (vulnFilterType !== 'all') {
      vulns = vulns.filter(v => v.type === vulnFilterType);
    }

    // 4. 审计状态筛选
    if (vulnFilterAuditStatus !== 'all') {
      const isAudited = (v: Vulnerability) => !!v.aiAssessment;
      if (vulnFilterAuditStatus === 'audited') {
        vulns = vulns.filter(isAudited);
      } else {
        vulns = vulns.filter(v => !isAudited(v));
      }
    }

    // 5. 只扫描 PHP 文件筛选
    if (vulnFilterPhpOnly) {
      vulns = vulns.filter(v => v.fileName?.endsWith('.php'));
    }

    return vulns;
  }, [
    currentProject.scanResult,
    vulnSearchQuery,
    vulnFilterLevel,
    vulnFilterType,
    vulnFilterAuditStatus,
    vulnFilterPhpOnly
  ]);

  const selectedVuln = useMemo(() => displayedVulns.find(v => v.id === currentProject.selectedVulnId), [displayedVulns, currentProject.selectedVulnId]);

  const fileTree = useMemo(() => {
    const root: FileNode = { name: currentProject.projectName, path: '', children: [] };
    
    // 去重：使用 Map 以文件路径为 key 保留最后一个
    const uniqueFiles = new Map<string, FileData>();
    currentProject.files.forEach(file => {
      uniqueFiles.set(file.name, file);
    });
    const dedupedFiles = Array.from(uniqueFiles.values());
    
    // 如果去重后有变化，更新项目文件列表
    if (dedupedFiles.length !== currentProject.files.length) {
      console.warn(`[fileTree] 检测到 ${currentProject.files.length - dedupedFiles.length} 个重复文件，已去重`);
    }
    
    dedupedFiles.forEach((file, index) => {
      const parts = file.name.split('/');
      let current = root;
      let currentPath = '';
      parts.forEach((part, i) => {
        currentPath = currentPath ? `${currentPath}/${part}` : part;
        if (i === parts.length - 1) current.children?.push({ name: part, path: currentPath, fileIndex: index });
        else {
          let folder = current.children?.find(c => c.name === part && c.children);
          if (!folder) { folder = { name: part, path: currentPath, children: [] }; current.children?.push(folder); }
          current = folder;
        }
      });
    });
    return root;
  }, [currentProject.files, currentProject.projectName]);

  useEffect(() => { loadHistory(); }, []);

  const loadHistory = async () => {
    const history = await dbService.getAllScans();
    setAllScans(history.sort((a, b) => b.timestamp - a.timestamp));
  };

  const [loadingScanId, setLoadingScanId] = useState<string | null>(null);

  const loadScanFromHistory = async (scan: ScanResult) => {
    setLoadingScanId(scan.id);
    try {
      // 按需加载文件内容（避免历史记录列表加载超时）
      const files = await dbService.loadScanFiles(scan.projectId);

      const projectState: ProjectState = {
        files: files,
        projectName: scan.projectName,
        scanResult: { ...scan, files },
        openFileIndices: files.length > 0 ? [0] : [],
        activeTabIndex: files.length > 0 ? 0 : -1,
        expandedFolders: new Set<string>(),
        selectedVulnId: null,
        batchSelectedIds: new Set<string>(),
        modifiedFiles: new Set<number>()
      };

      if (scan.isWebshellScan) {
        setWebshellState(projectState);
        setActiveTab('webshell');
      } else {
        setAuditState(projectState);
        setActiveTab('scan');
      }
    } catch (error) {
      console.error('Failed to load scan files:', error);
      alert('加载扫描记录失败，请重试');
    } finally {
      setLoadingScanId(null);
    }
  };

  const handleDeleteScan = async (e: React.MouseEvent, scan: ScanResult) => {
    e.stopPropagation();
    const scanType = scan.isWebshellScan ? 'WebShell扫描' : '代码审计';
    if (!window.confirm(`确定要删除这个${scanType}记录吗？此操作不可恢复。`)) return;

    try {
      await dbService.deleteScan(scan.id, scan.projectId);
      await loadHistory();
    } catch (error) {
      console.error('Failed to delete scan:', error);
      alert('删除失败，请重试');
    }
  };

  const handleEditorMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;
    
    // 添加 Ctrl+S / Cmd+S 保存快捷键
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
      handleSaveCurrentFile();
    });
  };
  
  // 处理编辑器内容变化
  const handleEditorChange = (value: string | undefined) => {
    if (currentFileIndex === -1 || !value) return;
    
    const currentContent = currentProject.files[currentFileIndex]?.content;
    if (value !== currentContent) {
      // 内容有变化，标记为已修改
      const newModified = new Set<number>(currentProject.modifiedFiles);
      newModified.add(currentFileIndex);
      updateProject({ modifiedFiles: newModified });
    }
  };
  
  // 保存当前文件
  const handleSaveCurrentFile = () => {
    if (currentFileIndex === -1 || !editorRef.current) return;
    
    const newContent = editorRef.current.getValue();
    const newFiles = [...currentProject.files];
    newFiles[currentFileIndex] = {
      ...newFiles[currentFileIndex],
      content: newContent
    };
    
    // 清除修改标记
    const newModified = new Set<number>(currentProject.modifiedFiles);
    newModified.delete(currentFileIndex);
    
    updateProject({ files: newFiles, modifiedFiles: newModified });
  };

  const anchorToVulnerability = (vuln: Vulnerability) => {
    // 使用函数式更新确保获取最新 state
    const updateFn = isWebshellView 
      ? (prev: ProjectState) => ({ ...prev, selectedVulnId: vuln.id })
      : (prev: ProjectState) => ({ ...prev, selectedVulnId: vuln.id });
    
    if (isWebshellView) setWebshellState(updateFn);
    else setAuditState(updateFn);

    // 使用仅文件名进行匹配，避免路径格式不一致问题（同时处理 Windows 和 Unix 路径）
    const vulnFileName = getBasename(vuln.fileName);
    
    // 获取当前最新的 files（使用函数式更新中的值）
    const currentFiles = isWebshellView ? webshellState.files : auditState.files;
    const fileIdx = currentFiles.findIndex(f => getBasename(f.name) === vulnFileName);
    const matchedFile = fileIdx !== -1 ? currentFiles[fileIdx] : null;
    
    console.log('[anchorToVulnerability] vulnFileName:', vulnFileName, 'fileIdx:', fileIdx, 'totalFiles:', currentFiles.length);
    
    if (fileIdx !== -1 && matchedFile) {
      // 计算需要展开的文件夹路径
      const normalizedFilePath = normalizePath(matchedFile.name);
      const pathParts = normalizedFilePath.split('/');
      const foldersToExpand = new Set<string>();
      let currentPath = '';
      // 逐级添加文件夹路径（不包括文件名）
      for (let i = 0; i < pathParts.length - 1; i++) {
        currentPath = currentPath ? `${currentPath}/${pathParts[i]}` : pathParts[i];
        foldersToExpand.add(currentPath);
      }
      
      // 直接在这里处理 openFile 逻辑，避免闭包问题
      const currentOpenIndices = isWebshellView ? webshellState.openFileIndices : auditState.openFileIndices;
      const currentExpanded = isWebshellView ? webshellState.expandedFolders : auditState.expandedFolders;
      const alreadyOpenIndex = currentOpenIndices.indexOf(fileIdx);
      
      // 合并已有的展开文件夹和新的文件夹
      const newExpandedFolders = new Set<string>([...currentExpanded, ...foldersToExpand]);
      
      if (alreadyOpenIndex !== -1) {
        // 文件已在标签页中，直接切换
        const activateFn = isWebshellView 
          ? (prev: ProjectState) => ({ ...prev, activeTabIndex: alreadyOpenIndex, expandedFolders: newExpandedFolders })
          : (prev: ProjectState) => ({ ...prev, activeTabIndex: alreadyOpenIndex, expandedFolders: newExpandedFolders });
        if (isWebshellView) setWebshellState(activateFn);
        else setAuditState(activateFn);
      } else {
        // 打开新文件
        const newOpenIndices = [...currentOpenIndices, fileIdx];
        const openFn = isWebshellView 
          ? (prev: ProjectState) => ({ ...prev, openFileIndices: newOpenIndices, activeTabIndex: newOpenIndices.length - 1, expandedFolders: newExpandedFolders })
          : (prev: ProjectState) => ({ ...prev, openFileIndices: newOpenIndices, activeTabIndex: newOpenIndices.length - 1, expandedFolders: newExpandedFolders });
        if (isWebshellView) setWebshellState(openFn);
        else setAuditState(openFn);
      }
      
      // 滚动文件树到对应的文件
      setTimeout(() => {
        if (fileTreeRef.current) {
          const fileElement = fileTreeRef.current.querySelector(`[data-file-index="${fileIdx}"]`) as HTMLElement;
          if (fileElement) {
            fileElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            // 添加临时高亮效果
            fileElement.style.backgroundColor = isDark ? 'rgba(16, 185, 129, 0.2)' : 'rgba(16, 185, 129, 0.15)';
            setTimeout(() => {
              fileElement.style.backgroundColor = '';
            }, 1500);
          }
        }
      }, 100);
    }

    setTimeout(() => {
      if (editorRef.current && monacoRef.current) {
        const editor = editorRef.current;
        const monaco = monacoRef.current;
        const model = editor.getModel();
        if (!model) return;
        const matches = model.findMatches(vuln.snippet, false, false, true, null, true);
        const bestMatch = matches.length > 0 
          ? matches.reduce((prev: any, curr: any) => Math.abs(curr.range.startLineNumber - vuln.line) < Math.abs(prev.range.startLineNumber - vuln.line) ? curr : prev)
          : null;
        const targetRange = bestMatch ? bestMatch.range : new monaco.Range(vuln.line, 1, vuln.line, model.getLineMaxColumn(vuln.line));
        decorationsRef.current = editor.deltaDecorations(decorationsRef.current, [{
          range: targetRange,
          options: { 
            isWholeLine: !bestMatch, className: isDark ? 'bg-rose-500/10' : 'bg-rose-500/15', 
            linesDecorationsClassName: `border-l-4 ${vuln.type.includes('Webshell') ? 'border-rose-600' : 'border-rose-500'}`,
            stickiness: monaco.editor.TrackedRangeStickiness.NeverGrowsWhenTypingAtEdges
          }
        }]);
        editor.revealRangeInCenter(targetRange, monaco.editor.ScrollType.Smooth);
        editor.setSelection(targetRange); editor.focus();
      }
    }, 300); // 增加延迟确保文件已加载
  };

  const openFile = (fileIndex: number) => {
    const alreadyOpenIndex = currentProject.openFileIndices.indexOf(fileIndex);
    if (alreadyOpenIndex !== -1) updateProject({ activeTabIndex: alreadyOpenIndex });
    else {
      const newOpenIndices = [...currentProject.openFileIndices, fileIndex];
      updateProject({ openFileIndices: newOpenIndices, activeTabIndex: newOpenIndices.length - 1 });
    }
  };

  const processFiles = async (rawFiles: FileList | File[], isZipMode: boolean = false) => {
    setIsImporting(true);
    try {
      const newFiles: FileData[] = [];

      // 处理ZIP文件
      if (isZipMode && rawFiles.length === 1 && rawFiles[0].name.endsWith('.zip')) {
        const zipFile = rawFiles[0];
        const zip = await JSZip.loadAsync(zipFile);
        const zipPromises: Promise<void>[] = [];

        zip.forEach((relativePath, zipEntry) => {
          if (!zipEntry.dir && relativePath.endsWith('.php')) {
            const promise = zipEntry.async('string').then(content => {
              newFiles.push({ name: relativePath, content });
            });
            zipPromises.push(promise);
          }
        });

        await Promise.all(zipPromises);

        if (newFiles.length > 0) {
          const newProjectName = zipFile.name.replace('.zip', '');
          updateProject({ files: newFiles, projectName: newProjectName, openFileIndices: [0], activeTabIndex: 0, scanResult: null, selectedVulnId: null, batchSelectedIds: new Set<string>(), expandedFolders: new Set<string>(), modifiedFiles: new Set<number>() });
          if (autoScanEnabled) setTimeout(() => handleScan(isWebshellView, newFiles, newProjectName), 100);
        }
      } else {
        // 处理普通文件或文件夹
        const promises = Array.from(rawFiles).map((file: any) => {
          const path = file.webkitRelativePath || file.name;
          return new Promise<void>((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => { newFiles.push({ name: path, content: e.target?.result as string }); resolve(); };
            reader.onerror = () => resolve(); reader.readAsText(file);
          });
        });
        await Promise.all(promises);
        if (newFiles.length > 0) {
          const newProjectName = (rawFiles[0] as any)?.webkitRelativePath?.split('/')[0] || "已导入项目";
          updateProject({ files: newFiles, projectName: newProjectName, openFileIndices: [0], activeTabIndex: 0, scanResult: null, selectedVulnId: null, batchSelectedIds: new Set<string>(), expandedFolders: new Set<string>(), modifiedFiles: new Set<number>() });
          if (autoScanEnabled) setTimeout(() => handleScan(isWebshellView, newFiles, newProjectName), 100);
        }
      }
    } finally { setIsImporting(false); if (fileInputRef.current) fileInputRef.current.value = ''; }
  };

  const handleScan = async (isWebshell: boolean = false, filesOverride?: FileData[], projectNameOverride?: string) => {
    const targetState = isWebshell ? webshellState : auditState;
    const targetFiles = filesOverride || targetState.files;
    const targetProjectName = projectNameOverride || targetState.projectName;
    if (targetFiles.length === 0) return;

    setIsScanning(true);
    setScanProgress(0);

    if (isWebshell) setWebshellState(prev => ({ ...prev, selectedVulnId: null, batchSelectedIds: new Set<string>() }));
    else setAuditState(prev => ({ ...prev, selectedVulnId: null, batchSelectedIds: new Set<string>() }));

    try {
      // 如果当前已有 scanResult，说明是从历史记录重新扫描，传入 projectId 进行覆盖
      const existingProjectId = targetState.scanResult?.projectId;
      
      const scanResult = await dbService.runBackendScan({
        files: targetFiles,
        projectName: targetProjectName,
        isWebshellScan: isWebshell,
        onProgress: (progress) => setScanProgress(Math.round(progress)),
        existingProjectId, // 传入现有项目ID进行覆盖扫描
      });

      if (isWebshell) setWebshellState(prev => ({ ...prev, scanResult }));
      else setAuditState(prev => ({ ...prev, scanResult }));

      await loadHistory();
    } catch (error) {
      console.error('Failed to run backend scan:', error);
      alert('扫描失败，请检查后端服务是否正常并重试。');
    } finally {
      setIsScanning(false);
    }
  };

  const runBatchAiAudit = async () => {
    if (!currentProject.scanResult || currentProject.batchSelectedIds.size === 0) return;
    setIsBatchAnalyzing(true);
    shouldStopBatchRef.current = false; // 重置停止标记

    const targets = currentProject.scanResult.vulnerabilities.filter(v => currentProject.batchSelectedIds.has(v.id));
    const needAuditTargets = targets.filter(v => !v.aiAssessment);
    const alreadyAuditedCount = targets.length - needAuditTargets.length;

    setBatchProgress({ current: alreadyAuditedCount, total: targets.length });

    const aiService = new AIService();
    const originalVulns = currentProject.scanResult.vulnerabilities;
    // 使用 Map 存储每个漏洞的审计结果，避免并发更新数组导致竞态条件
    const auditResultsMap = new Map<string, { isFalsePositive: boolean; rawReport: string; poc?: string; payload?: string; auditedAt: number; error?: string }>();

    // 并发控制参数
    const CONCURRENCY_LIMIT = 2; // 降低并发数以避免触发 API 限流
    const REQUEST_DELAY_MS = 1000; // 增加请求间隔到 1 秒
    const ESTIMATED_TIME_PER_REQUEST = 5000; // 预估每个请求 5 秒（考虑重试）
    const MAX_RETRIES = 2; // 单个请求最大重试次数

    // 计算预估完成时间
    const totalTimeEstimate = Math.ceil((needAuditTargets.length * ESTIMATED_TIME_PER_REQUEST) / CONCURRENCY_LIMIT);
    setBatchTimeEstimate(totalTimeEstimate);
    setBatchStartTime(Date.now());
    setBatchRemainingTime(totalTimeEstimate);

    // 并发控制执行 - 分批处理
    const executeWithConcurrency = async () => {
      let completedCount = alreadyAuditedCount;

      // 将任务分成多个批次，每批最多 CONCURRENCY_LIMIT 个
      for (let i = 0; i < needAuditTargets.length; i += CONCURRENCY_LIMIT) {
        // 检查是否应该停止
        if (shouldStopBatchRef.current) {
          console.log('[BatchAudit] 批量审计已停止');
          break;
        }
        
        const batch = needAuditTargets.slice(i, i + CONCURRENCY_LIMIT);

        // 并发执行当前批次
        const batchPromises = batch.map(async (vuln) => {
          setReviewingVulnIds(prev => new Set(prev).add(vuln.id));
          try {
            // 检查是否应该停止（任务开始前）
            if (shouldStopBatchRef.current) {
              console.log(`[BatchAudit] 跳过 ${vuln.id} (已停止)`);
              return;
            }

            const getBasenameBatch = (path: string) => path?.replace(/\\/g, '/').split('/').pop() || path;
            const vulnFileNameForBatch = getBasename(vuln.fileName);
            const fileContent = currentProject.files.find(f => getBasename(f.name) === vulnFileNameForBatch)?.content || "";
            let retries = 0;
            let success = false;

            // 重试逻辑
            while (retries <= MAX_RETRIES && !success) {
              // 检查是否应该停止（重试前）
              if (shouldStopBatchRef.current) {
                console.log(`[BatchAudit] 中断 ${vuln.id} (已停止)`);
                break;
              }

              try {
                if (retries > 0) {
                  console.log(`[BatchAudit] 重试 ${vuln.id} (第 ${retries} 次)`);
                  // 重试前等待更长时间
                  await new Promise(resolve => setTimeout(resolve, REQUEST_DELAY_MS * retries));
                }
                const result = await aiService.reviewVulnerability(vuln, fileContent);
                // 将结果存入 Map 而不是直接更新数组
                auditResultsMap.set(vuln.id, result);
                success = true;
              } catch (error: any) {
                retries++;
                console.error(`[BatchAudit] Audit error (attempt ${retries}): ${vuln.id}`, error);

                // 如果达到最大重试次数，保存错误信息
                if (retries > MAX_RETRIES) {
                  auditResultsMap.set(vuln.id, {
                    isFalsePositive: false,
                    rawReport: error.message || 'AI 审计失败',
                    auditedAt: Date.now(),
                    error: error.message || 'AI 审计失败'
                  });
                }
              }
            }

            completedCount++;
            setBatchProgress({ current: completedCount, total: targets.length });
          } finally {
            setReviewingVulnIds(prev => {
              const next = new Set(prev);
              next.delete(vuln.id);
              return next;
            });
          }
        });

        // 等待当前批次全部完成
        await Promise.all(batchPromises);

        // 批次间隔（如果不是最后一个批次）
        if (i + CONCURRENCY_LIMIT < needAuditTargets.length) {
          await new Promise(resolve => setTimeout(resolve, REQUEST_DELAY_MS));
        }
      }
    };

    await executeWithConcurrency();

    // 所有任务完成后（或被停止后），一次性合并结果到漏洞列表
    const updatedVulns = originalVulns.map(v => {
      const auditResult = auditResultsMap.get(v.id);
      if (auditResult) {
        return { ...v, aiAssessment: auditResult };
      }
      return v;
    });
    await syncScanToDb({ ...currentProject.scanResult, vulnerabilities: updatedVulns });
    setIsBatchAnalyzing(false);
    setBatchTimeEstimate(null);
    setBatchStartTime(null);
    setBatchRemainingTime(null);
    setReviewingVulnIds(new Set());
    shouldStopBatchRef.current = false; // 重置停止标记
  };
  
  // 停止批量审计
  const stopBatchAiAudit = () => {
    shouldStopBatchRef.current = true;
    console.log('[BatchAudit] 用户请求停止批量审计');
  };

  const renderTree = (node: FileNode) => {
    if (node.children) {
      const isExpanded = currentProject.expandedFolders.has(node.path);
      return (
        <div key={node.path} className="select-none">
          <div onClick={() => { const next = new Set<string>(currentProject.expandedFolders); if (next.has(node.path)) next.delete(node.path); else next.add(node.path); updateProject({ expandedFolders: next }); }} className={`flex items-center gap-1.5 px-4 py-1.5 cursor-pointer transition-colors ${isDark ? 'text-zinc-400 hover:text-white hover:bg-zinc-900' : 'text-zinc-600 hover:text-zinc-900 hover:bg-zinc-100'}`}>
            <svg className={`w-3 h-3 transition-transform duration-200 ${isExpanded ? 'rotate-90' : ''} opacity-60`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 5l7 7-7 7" /></svg>
            <svg className={`w-4 h-4 ${isExpanded ? 'text-amber-400' : (isDark ? 'text-zinc-600' : 'text-zinc-400')}`} fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" /></svg>
            <span className="text-[11px] font-bold truncate">{node.name}</span>
          </div>
          {isExpanded && <div className={`pl-2 ml-3.5 border-l ${isDark ? 'border-zinc-800' : 'border-zinc-200'}`}>{node.children.map(child => renderTree(child))}</div>}
        </div>
      );
    } else {
      const isActive = node.fileIndex !== undefined && currentProject.activeTabIndex !== -1 && currentProject.openFileIndices[currentProject.activeTabIndex] === node.fileIndex;
      return (
        <div key={node.path} data-file-index={node.fileIndex} onClick={() => node.fileIndex !== undefined && openFile(node.fileIndex)} className={`group flex items-center gap-2 px-8 py-1.5 cursor-pointer transition-colors relative ${isActive ? (isDark ? 'bg-emerald-500/10 text-emerald-400' : 'bg-emerald-50 text-emerald-700') : (isDark ? 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900' : 'text-zinc-600 hover:text-zinc-900 hover:bg-zinc-100')}`}>
          <div className="w-3.5 flex justify-center shrink-0">{node.name.endsWith('.php') ? <svg className="w-3.5 h-3.5 text-indigo-400 opacity-80" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg> : <svg className="w-3.5 h-3.5 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>}</div>
          <span className={`text-[11px] truncate ${isActive ? 'font-black' : 'font-medium'}`}>{node.name}</span>
          {isActive && <div className={`absolute left-0 top-0 bottom-0 w-0.5 ${isDark ? 'bg-emerald-500' : 'bg-emerald-600'}`}></div>}
        </div>
      );
    }
  };

  return (
    <Layout activeTab={activeTab} onTabChange={setActiveTab} theme={theme} onThemeToggle={() => { const next = theme === 'dark' ? 'light' : 'dark'; setTheme(next); localStorage.setItem('phpsentinel_theme', next); }}>
      
      {/* 核心审计/木马猎手容器 (Keep-Alive) */}
      <div className={`flex flex-col h-full overflow-hidden transition-all ${isScanOrWebshell ? 'block' : 'hidden'}`}>
        <header className={`h-14 flex items-center justify-between px-6 border-b shrink-0 transition-colors ${isDark ? 'border-zinc-900 bg-zinc-950' : 'border-zinc-200 bg-white shadow-sm'}`}>
          <div className="flex items-center gap-4">
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors ${isDark ? 'bg-zinc-900 border-zinc-800' : 'bg-zinc-100 border-zinc-200'}`}>
               <span className="text-[10px] font-black text-zinc-500 uppercase">{isWebshellView ? 'Backdoor Target' : 'Audit Target'}</span>
               <span className={`text-[11px] font-bold tracking-tight truncate max-w-[200px] ${isDark ? 'text-zinc-100' : 'text-zinc-900'}`}>{currentProject.projectName}</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {isScanning && <div className={`w-32 h-1.5 rounded-full overflow-hidden border ${isDark ? 'bg-zinc-900 border-zinc-800' : 'bg-zinc-200 border-zinc-300'}`}><div className={`h-full transition-all duration-300 ${isWebshellView ? 'bg-rose-500' : 'bg-emerald-500'}`} style={{ width: `${scanProgress}%` }}></div></div>}
            <button onClick={() => handleScan(isWebshellView)} disabled={isScanning || currentProject.files.length === 0} className={`h-9 px-6 rounded-xl text-[11px] font-black transition-all flex items-center gap-2 shadow-xl active:scale-95 uppercase tracking-widest ${isWebshellView ? 'bg-rose-600 hover:bg-rose-500 text-white' : (isDark ? 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950' : 'bg-emerald-600 hover:bg-emerald-700 text-white')}`}>{isScanning ? '执行中...' : (isWebshellView ? '启动木马扫描' : '启动安全审计')}</button>
          </div>
        </header>
        <div className="flex-grow flex overflow-hidden">
          <aside style={{ width: leftWidth }} className={`relative border-r flex flex-col shrink-0 transition-colors ${isDark ? 'border-zinc-900 bg-zinc-950' : 'border-zinc-200 bg-zinc-50'}`}>
            <div onMouseDown={() => { isResizing.current = 'left'; document.body.style.cursor = 'col-resize'; }} className={`absolute top-0 right-[-3px] bottom-0 w-[6px] cursor-col-resize z-50 transition-colors hover:bg-emerald-500/50`} />
            <div className={`p-4 border-b flex flex-col gap-3 ${isDark ? 'border-zinc-900' : 'border-zinc-200'}`}>
               <div className="flex items-center justify-between"><span className="text-[10px] font-black text-zinc-500 uppercase">资源导入</span><div className="flex items-center gap-1"><button title="上传文件夹" onClick={() => fileInputRef.current?.click()} className="p-1.5 text-zinc-500 hover:text-emerald-400 border rounded border-transparent hover:border-emerald-500/30"><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" /></svg></button><button title="上传PHP文件或ZIP" onClick={() => zipInputRef.current?.click()} className="p-1.5 text-zinc-500 hover:text-emerald-400 border rounded border-transparent hover:border-emerald-500/30"><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" /></svg></button><input type="file" ref={fileInputRef} onChange={(e) => e.target.files && processFiles(e.target.files, false)} multiple {...({ webkitdirectory: "" } as any)} className="hidden" /><input type="file" ref={zipInputRef} onChange={(e) => e.target.files && processFiles(e.target.files, true)} accept=".php,.zip" multiple className="hidden" /></div></div>
               <div className="flex flex-col gap-2"><div className="flex items-center gap-2"><input type="checkbox" id="autoScan" checked={autoScanEnabled} onChange={(e) => setAutoScanEnabled(e.target.checked)} className="w-3.5 h-3.5 rounded border" /><label htmlFor="autoScan" className="text-[10px] font-medium text-zinc-500 cursor-pointer">自动扫描</label></div></div>
            </div>
            <div ref={fileTreeRef} className="flex-grow overflow-y-auto py-2 custom-scrollbar">{fileTree.children?.map(child => renderTree(child))}</div>
          </aside>
          <section className="flex-grow flex flex-col overflow-hidden relative">
             <div className={`h-9 flex items-center justify-between overflow-x-auto no-scrollbar shrink-0 border-b ${isDark ? 'bg-zinc-950 border-zinc-900' : 'bg-zinc-100 border-zinc-200'}`}>
                <div className="flex items-center h-full">
                  {currentProject.openFileIndices.map((fileIdx, tabIdx) => {
                    const isModified = currentProject.modifiedFiles.has(fileIdx);
                    return (
                      <div key={tabIdx} onClick={() => updateProject({ activeTabIndex: tabIdx })} className={`h-full min-w-[140px] flex items-center justify-between px-3 border-r cursor-pointer transition-all ${currentProject.activeTabIndex === tabIdx ? (isDark ? 'bg-zinc-900 text-zinc-100 border-b-2 border-emerald-500' : 'bg-white text-zinc-900 border-b-2 border-emerald-600') : 'text-zinc-500 border-zinc-900'}`}>
                        <span className="text-[11px] font-medium truncate">{currentProject.files[fileIdx]?.name.split('/').pop()}{isModified && '*'}</span>
                        <button onClick={(e) => { e.stopPropagation(); const next = currentProject.openFileIndices.filter((_, i) => i !== tabIdx); updateProject({ openFileIndices: next, activeTabIndex: next.length === 0 ? -1 : (currentProject.activeTabIndex === tabIdx ? Math.max(0, tabIdx - 1) : (currentProject.activeTabIndex > tabIdx ? currentProject.activeTabIndex - 1 : currentProject.activeTabIndex)) }); }} className="p-0.5 hover:bg-zinc-800 rounded"><svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" /></svg></button>
                      </div>
                    );
                  })}
                </div>
                {/* 保存按钮 */}
                {currentFileIndex !== -1 && (
                  <button 
                    onClick={handleSaveCurrentFile}
                    disabled={!currentProject.modifiedFiles.has(currentFileIndex)}
                    className={`mr-2 px-3 py-1 text-[10px] font-bold rounded flex items-center gap-1.5 transition-all ${
                      currentProject.modifiedFiles.has(currentFileIndex)
                        ? (isDark ? 'bg-emerald-600 hover:bg-emerald-500 text-white' : 'bg-emerald-600 hover:bg-emerald-700 text-white')
                        : (isDark ? 'bg-zinc-800 text-zinc-600 cursor-not-allowed' : 'bg-zinc-300 text-zinc-500 cursor-not-allowed')
                    }`}
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                    </svg>
                    保存
                  </button>
                )}
             </div>
             <div className="flex-grow">
               {currentFileIndex !== -1 && (
                 <Editor 
                   height="100%"
                   theme={isDark ? 'vs-dark' : 'light'}
                   defaultLanguage="php"
                   path={currentProject.files[currentFileIndex].name}
                   defaultValue={currentProject.files[currentFileIndex].content}
                   onMount={handleEditorMount}
                   onChange={handleEditorChange}
                   options={{ fontSize: 14, minimap: { enabled: true }, automaticLayout: true }}
                 />
               )}
             </div>
          </section>
          <aside style={{ width: rightWidth }} className={`relative border-l flex flex-col shrink-0 transition-colors ${isDark ? 'border-zinc-900 bg-zinc-950' : 'border-zinc-200 bg-white'}`}>
             <div onMouseDown={() => { isResizing.current = 'right'; document.body.style.cursor = 'col-resize'; }} className={`absolute top-0 left-[-3px] bottom-0 w-[6px] cursor-col-resize z-50 transition-colors hover:bg-emerald-500/50`} />
              <div className={`h-auto px-5 py-3 flex flex-col gap-3 border-b shrink-0 ${isDark ? 'bg-zinc-900/10 border-zinc-900' : 'bg-zinc-50 border-zinc-200'}`}>
                 {/* 标题行 */}
                 <div className="flex items-center justify-between">
                   <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">{isWebshellView ? '检出后门' : '审计发现'}</span>
                   <div className="flex items-center gap-2">
                     {/* 统计标签 */}
                     {vulnStats.critical > 0 && (
                       <span className="px-2 py-0.5 text-[9px] font-black rounded bg-rose-500/10 text-rose-500 border border-rose-500/20">严重 {vulnStats.critical}</span>
                     )}
                     {vulnStats.high > 0 && (
                       <span className="px-2 py-0.5 text-[9px] font-black rounded bg-orange-500/10 text-orange-500 border border-orange-500/20">高危 {vulnStats.high}</span>
                     )}
                     {vulnStats.audited > 0 && (
                       <span className="px-2 py-0.5 text-[9px] font-black rounded bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">已审 {vulnStats.audited}</span>
                     )}
                     <span className={`px-2 py-0.5 text-[10px] font-black rounded border ${isWebshellView ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' : 'bg-rose-50 text-rose-600 border-rose-200'}`}>{displayedVulns.length}</span>
                   </div>
                 </div>

                 {/* 批量选择按钮 */}
                 {currentProject.scanResult && currentProject.scanResult.vulnerabilities.length > 0 && (
                   <div className="flex items-center gap-2">
                     <button
                       onClick={() => {
                         const allIds = new Set<string>(displayedVulns.map(v => v.id));
                         updateProject({ batchSelectedIds: allIds });
                       }}
                       className={`px-2 py-1 text-[9px] font-bold rounded border transition-colors ${
                         isDark
                           ? 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-300'
                           : 'bg-white border-zinc-200 text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900'
                       }`}
                     >
                       全选
                     </button>
                     <button
                       onClick={() => {
                         const criticalIds = new Set<string>(displayedVulns.filter(v => v.level === RiskLevel.CRITICAL).map(v => v.id));
                         updateProject({ batchSelectedIds: criticalIds });
                       }}
                       className={`px-2 py-1 text-[9px] font-bold rounded border transition-colors ${
                         isDark
                           ? 'bg-rose-500/10 border-rose-500/30 text-rose-400 hover:bg-rose-500/20'
                           : 'bg-rose-50 border-rose-200 text-rose-600 hover:bg-rose-100'
                       }`}
                     >
                       严重
                     </button>
                     <button
                       onClick={() => {
                         const highIds = new Set<string>(displayedVulns.filter(v => v.level === RiskLevel.HIGH).map(v => v.id));
                         updateProject({ batchSelectedIds: highIds });
                       }}
                       className={`px-2 py-1 text-[9px] font-bold rounded border transition-colors ${
                         isDark
                           ? 'bg-orange-500/10 border-orange-500/30 text-orange-400 hover:bg-orange-500/20'
                           : 'bg-orange-50 border-orange-200 text-orange-600 hover:bg-orange-100'
                       }`}
                     >
                       高危
                     </button>
                     <button
                       onClick={() => updateProject({ batchSelectedIds: new Set<string>() })}
                       className={`px-2 py-1 text-[9px] font-bold rounded border transition-colors ${
                         isDark
                           ? 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-300'
                           : 'bg-white border-zinc-200 text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900'
                       }`}
                     >
                       清空
                     </button>
                     {currentProject.batchSelectedIds.size > 0 && (
                       <span className={`ml-auto text-[9px] font-medium ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`}>
                         已选 {currentProject.batchSelectedIds.size} 个
                       </span>
                     )}
                   </div>
                 )}

                 {/* 搜索框 */}
                 <div className="relative">
                   <input
                     type="text"
                     value={vulnSearchQuery}
                     onChange={(e) => setVulnSearchQuery(e.target.value)}
                     placeholder="搜索文件名、类型或描述..."
                     className={`w-full px-3 py-2 pl-8 text-[11px] rounded-lg border outline-none transition-all ${
                       isDark
                         ? 'bg-zinc-950 border-zinc-800 text-zinc-300 placeholder:text-zinc-600 focus:border-emerald-500/50'
                         : 'bg-white border-zinc-200 text-zinc-700 placeholder:text-zinc-400 focus:border-emerald-500'
                     }`}
                   />
                   <svg className={`absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 ${isDark ? 'text-zinc-600' : 'text-zinc-400'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                     <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                   </svg>
                   {vulnSearchQuery && (
                     <button
                       onClick={() => setVulnSearchQuery('')}
                       className={`absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded ${isDark ? 'hover:bg-zinc-800 text-zinc-500' : 'hover:bg-zinc-100 text-zinc-400'}`}
                     >
                       <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                         <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                       </svg>
                     </button>
                   )}
                 </div>

                 {/* 筛选器 */}
                 <div className="flex flex-wrap gap-2">
                   {/* 风险等级筛选 */}
                   <select
                     value={vulnFilterLevel}
                     onChange={(e) => setVulnFilterLevel(e.target.value as RiskLevel | 'all')}
                     className={`px-2 py-1.5 text-[10px] rounded-lg border outline-none cursor-pointer ${
                       isDark
                         ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
                         : 'bg-white border-zinc-200 text-zinc-600 hover:border-zinc-300'
                     }`}
                   >
                     <option value="all">全部等级</option>
                     <option value={RiskLevel.CRITICAL}>严重</option>
                     <option value={RiskLevel.HIGH}>高危</option>
                     <option value={RiskLevel.MEDIUM}>中危</option>
                     <option value={RiskLevel.LOW}>低危</option>
                   </select>

                   {/* 漏洞类型筛选 */}
                   <select
                     value={vulnFilterType}
                     onChange={(e) => setVulnFilterType(e.target.value)}
                     className={`px-2 py-1.5 text-[10px] rounded-lg border outline-none cursor-pointer max-w-[120px] ${
                       isDark
                         ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
                         : 'bg-white border-zinc-200 text-zinc-600 hover:border-zinc-300'
                     }`}
                   >
                     <option value="all">全部类型</option>
                     {uniqueVulnTypes.map(type => (
                       <option key={type} value={type}>{type}</option>
                     ))}
                   </select>

                   {/* 审计状态筛选 */}
                   <select
                     value={vulnFilterAuditStatus}
                     onChange={(e) => setVulnFilterAuditStatus(e.target.value as 'all' | 'audited' | 'unaudited')}
                     className={`px-2 py-1.5 text-[10px] rounded-lg border outline-none cursor-pointer ${
                       isDark
                         ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
                         : 'bg-white border-zinc-200 text-zinc-600 hover:border-zinc-300'
                     }`}
                   >
                     <option value="all">全部状态</option>
                     <option value="audited">已审计</option>
                     <option value="unaudited">未审计</option>
                   </select>

                   {/* 只扫描 PHP 文件 */}
                   <label className={`flex items-center gap-1.5 px-2 py-1.5 text-[10px] rounded-lg border cursor-pointer select-none ${
                     vulnFilterPhpOnly
                       ? (isDark ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400' : 'bg-indigo-50 border-indigo-200 text-indigo-600')
                       : (isDark ? 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700' : 'bg-white border-zinc-200 text-zinc-600 hover:border-zinc-300')
                   }`}>
                     <input
                       type="checkbox"
                       checked={vulnFilterPhpOnly}
                       onChange={(e) => setVulnFilterPhpOnly(e.target.checked)}
                       className="w-3 h-3 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                     />
                     <span>仅PHP</span>
                   </label>

                   {/* 重置按钮 */}
                   {(vulnSearchQuery || vulnFilterLevel !== 'all' || vulnFilterType !== 'all' || vulnFilterAuditStatus !== 'all' || vulnFilterPhpOnly) && (
                     <button
                       onClick={() => {
                         setVulnSearchQuery('');
                         setVulnFilterLevel('all');
                         setVulnFilterType('all');
                         setVulnFilterAuditStatus('all');
                         setVulnFilterPhpOnly(false);
                       }}
                       className={`px-2 py-1.5 text-[10px] font-medium rounded-lg border transition-colors ${
                         isDark
                           ? 'bg-zinc-900 border-zinc-800 text-zinc-500 hover:text-zinc-300 hover:border-zinc-600'
                           : 'bg-zinc-100 border-zinc-200 text-zinc-600 hover:text-zinc-800 hover:border-zinc-300'
                       }`}
                     >
                       重置
                     </button>
                   )}
                 </div>
              </div>
             <div className="flex-grow overflow-y-auto custom-scrollbar p-3 space-y-2">
                {displayedVulns.map(vuln => <VulnerabilityItem key={vuln.id} vuln={vuln} isSelected={currentProject.selectedVulnId === vuln.id} isChecked={currentProject.batchSelectedIds.has(vuln.id)} isAuditing={reviewingVulnIds.has(vuln.id)} onCheck={(checked) => { const next = new Set<string>(currentProject.batchSelectedIds); if (checked) next.add(vuln.id); else next.delete(vuln.id); updateProject({ batchSelectedIds: next }); }} onClick={() => anchorToVulnerability(vuln)} theme={theme} />)}
             </div>
             {currentProject.batchSelectedIds.size > 0 && (
               <div className={`p-4 border-t flex flex-col gap-2 ${isDark ? 'bg-zinc-950 border-zinc-900' : 'bg-white border-zinc-200'}`}>
                  {isBatchAnalyzing && (
                    <div className="flex flex-col gap-1.5">
                      <div className={`w-full h-2 rounded-full overflow-hidden border ${isDark ? 'bg-zinc-900 border-zinc-800' : 'bg-zinc-100 border-zinc-200'}`}>
                        <div
                          className="h-full bg-emerald-500 transition-all duration-300"
                          style={{ width: `${(batchProgress.current / batchProgress.total) * 100}%` }}
                        />
                      </div>
                      <div className="flex justify-between items-center text-[10px] text-zinc-500">
                        <span>正在复核: {batchProgress.current} / {batchProgress.total}</span>
                        <span>{Math.round((batchProgress.current / batchProgress.total) * 100)}%</span>
                      </div>
                      {batchRemainingTime !== null && (
                        <div className="text-[9px] text-zinc-400">
                          预计剩余: {batchRemainingTime} 秒
                          (并发: 3, 间隔: 500ms)
                        </div>
                      )}
                    </div>
                  )}
                  {isBatchAnalyzing ? (
                    <div className="flex gap-2">
                      <button 
                        onClick={stopBatchAiAudit} 
                        className={`flex-1 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest bg-rose-500 text-white shadow-lg transition-all hover:bg-rose-400 animate-pulse`}
                      >
                        停止审计 ({batchProgress.current}/{batchProgress.total})
                      </button>
                    </div>
                  ) : (
                    <button 
                      onClick={runBatchAiAudit} 
                      className={`w-full py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest bg-emerald-500 text-zinc-950 shadow-lg transition-all hover:bg-emerald-400`}
                    >
                      批量 AI 复核 ({currentProject.batchSelectedIds.size})
                    </button>
                  )}
               </div>
             )}
          </aside>
          <div style={{ width: selectedVuln ? detailWidth : 0 }} className={`fixed inset-y-0 right-0 z-[100] transform transition-all duration-300 border-l shadow-2xl flex flex-col ${selectedVuln ? 'translate-x-0' : 'translate-x-full'} ${isDark ? 'bg-zinc-950 border-zinc-800' : 'bg-white border-zinc-200'}`}>
             {selectedVuln && (
               <div onMouseDown={() => { isResizing.current = 'detail'; document.body.style.cursor = 'col-resize'; }} className={`absolute top-0 left-[-3px] bottom-0 w-[6px] cursor-col-resize z-[110] transition-colors hover:bg-emerald-500/50`} />
             )}
             <header className={`h-14 px-6 flex items-center justify-between border-b shrink-0 ${isDark ? 'bg-zinc-900/40 border-zinc-800' : 'bg-zinc-50 border-zinc-200'}`}>
                <h4 className={`text-[12px] font-black uppercase tracking-widest ${isDark ? 'text-white' : 'text-zinc-900'}`}>{isWebshellView ? '木马风险鉴定报告' : '深度审计报告'}</h4>
                <button onClick={() => updateProject({ selectedVulnId: null })} className="p-2 text-zinc-500 hover:text-white rounded-lg transition-colors"><svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
             </header>
             <div className="flex-grow overflow-hidden">
                {selectedVuln && <VulnerabilityCard vuln={selectedVuln} codeContext={(() => { const getBasenameCtx = (path: string) => path?.replace(/\\/g, '/').split('/').pop() || path; const selVulnFileName = getBasename(selectedVuln.fileName); return currentProject.files.find(f => getBasename(f.name) === selVulnFileName)?.content || ""; })()} isAuditing={reviewingVulnIds.has(selectedVuln.id)} onAiUpdate={async (id, res) => { const next = currentProject.scanResult?.vulnerabilities.map(v => v.id === id ? { ...v, aiAssessment: res } : v); if (currentProject.scanResult) await syncScanToDb({ ...currentProject.scanResult, vulnerabilities: next || [] }); }} onChatUpdate={async (id, hist) => { const next = currentProject.scanResult?.vulnerabilities.map(v => v.id === id ? { ...v, chatHistory: hist } : v); if (currentProject.scanResult) await syncScanToDb({ ...currentProject.scanResult, vulnerabilities: next || [] }); }} onAiReviewStateChange={(id, isReviewing) => { setReviewingVulnIds(prev => { const next = new Set(prev); if (isReviewing) next.add(id); else next.delete(id); return next; }); }} theme={theme} />}
             </div>
          </div>
        </div>
      </div>

      {/* 网络实验室 (Keep-Alive) */}
      <div className={`h-full overflow-hidden transition-all ${activeTab === 'network' ? 'block' : 'hidden'}`}>
        <NetworkLab theme={theme} />
      </div>

      {/* 其他单次渲染标签 */}
      <div className={`h-full overflow-y-auto custom-scrollbar transition-all ${['home', 'dashboard', 'rules', 'history', 'settings'].includes(activeTab) ? 'block' : 'hidden'}`}>
         {activeTab === 'home' && <div className="p-12 h-full"><Home theme={theme} scans={allScans} onTabChange={setActiveTab} onLoadScan={loadScanFromHistory} /></div>}
         {activeTab === 'dashboard' && <div className="p-12 h-full"><Dashboard scans={allScans} theme={theme} /></div>}
         {activeTab === 'rules' && <div className="p-12 h-full"><RuleConfig theme={theme} /></div>}
         {activeTab === 'history' && (
           <div className="p-12 h-full max-w-5xl mx-auto space-y-8">
             <h2 className={`text-4xl font-black tracking-tighter ${isDark ? 'text-white' : 'text-zinc-900'}`}>审计存档</h2>
             <div className="grid grid-cols-1 gap-4">
                {allScans.map(scan => (
                  <div key={scan.id} onClick={() => loadScanFromHistory(scan)} className={`p-8 rounded-[32px] border transition-all cursor-pointer flex items-center justify-between group ${isDark ? 'bg-zinc-900/50 border-zinc-800 hover:border-emerald-500/40' : 'bg-white border-zinc-200 hover:border-emerald-300'}`}>
                     <div className="flex items-center gap-6">
                       <div className={`w-16 h-16 border rounded-2xl flex items-center justify-center ${scan.isWebshellScan ? 'bg-rose-500/10 border-rose-500/30 text-rose-500' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500'}`}>
                         <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                           <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={scan.isWebshellScan ? "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" : "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"} />
                         </svg>
                       </div>
                       <div>
                         <div className="flex items-center gap-3 mb-1">
                           <h4 className="font-black text-2xl">{scan.projectName}</h4>
                          <span className={`px-2 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider ${scan.isWebshellScan ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'}`}>
                            {scan.isWebshellScan ? 'WebShell扫描' : '代码审计'}
                          </span>
                          <span className={`px-2 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider ${scan.isWebshellScan ? 'bg-rose-500/5 text-rose-400 border border-rose-500/15' : 'bg-blue-500/10 text-blue-500 border border-blue-500/20'}`}>
                            {scan.isWebshellScan ? '规则引擎' : 'AST引擎'}
                          </span>
                         </div>
                         <p className="text-sm text-zinc-500">{new Date(scan.timestamp).toLocaleString()} • {scan.fileCount || scan.files.length} 个文件</p>
                       </div>
                     </div>
                     <div className="flex items-center gap-4">
                       <div className="text-right">
                         <p className="text-[10px] font-black text-zinc-400 uppercase">检出</p>
                         <p className={`text-4xl font-black ${scan.isWebshellScan ? 'text-rose-500' : 'text-emerald-500'}`}>{scan.stats.total}</p>
                       </div>
                       <button
                         onClick={(e) => handleDeleteScan(e, scan)}
                         className={`p-3 rounded-xl opacity-0 group-hover:opacity-100 transition-all ${isDark ? 'hover:bg-rose-500/10 text-zinc-600 hover:text-rose-500' : 'hover:bg-rose-50 text-zinc-400 hover:text-rose-600'}`}
                         title={`删除${scan.isWebshellScan ? 'WebShell扫描' : '代码审计'}记录`}
                       >
                         <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                           <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                         </svg>
                       </button>
                     </div>
                  </div>
                ))}
               {allScans.length === 0 && <div className="p-32 border-2 border-dashed border-zinc-800 text-center opacity-30 font-bold uppercase">暂无存档</div>}
             </div>
           </div>
         )}
         {activeTab === 'settings' && <div className="p-12 h-full"><Settings theme={theme} /></div>}
      </div>
    </Layout>
  );
};

export default App;
