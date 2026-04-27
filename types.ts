export type Theme = 'light' | 'dark';

export type ApiProviderType = 'custom-openai';

export interface ApiProfile {
  id: string;
  name: string;
  type: ApiProviderType;
  baseUrl?: string;
  apiKey?: string;
  modelName?: string;
}

export interface ApiProviderConfig {
  activeProfileId: string;
  profiles: ApiProfile[];
}

export const VulnerabilityType = {
  SQL_INJECTION: 'SQL 注入',
  XSS: '跨站脚本攻击 (XSS)',
  CODE_EXECUTION: '远程代码执行 (RCE)',
  FILE_INCLUSION: '文件包含 (LFI/RFI)',
  SENSITIVE_CALL: '敏感函数调用',
  UNTRUSTED_INPUT: '不可信输入源',
  SSRF: '服务端请求伪造 (SSRF)',
  DESERIALIZATION: '不安全的反序列化',
  PATH_TRAVERSAL: '路径穿越/任意文件操作',
  WEAK_CRYPTO: '弱加密/哈希算法',
  HEADER_INJECTION: 'HTTP 头部注入',
  LDAP_INJECTION: 'LDAP 注入',
  FILE_UPLOAD: '不安全的文件上传',
  WEBSHELL: 'Webshell 恶意后门',
  CUSTOM: '自定义规则'
} as const;

export type VulnerabilityType = typeof VulnerabilityType[keyof typeof VulnerabilityType];

export const RiskLevel = {
  CRITICAL: '严重',
  HIGH: '高危',
  MEDIUM: '中危',
  LOW: '低危',
  INFO: '提示'
} as const;

export type RiskLevel = typeof RiskLevel[keyof typeof RiskLevel];

export interface Message {
  role: 'user' | 'model';
  text: string;
}

export interface Rule {
  id: string;
  name: string;
  pattern: string; 
  type: VulnerabilityType;
  level: RiskLevel;
  enabled: boolean;
  isBuiltIn: boolean;
  description?: string;
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  level: RiskLevel;
  line: number;
  fileName: string;
  snippet: string;
  description: string;
  source: string; 
  sink: string;   
  aiAssessment?: {
    isFalsePositive: boolean;
    rawReport: string;
    poc?: string;       // 验证方法 (curl/httpie)
    payload?: string;   // 攻击载荷 (SQL/XSS/RCE)
    auditedAt?: number;
    error?: string;     // 审计错误信息
  };
  chatHistory?: Message[];
}

export interface FileData {
  name: string;
  content: string;
}

export interface ScanResult {
  id: string;
  projectId: string;
  timestamp: number;
  projectName: string;
  files: FileData[];
  vulnerabilities: Vulnerability[];
  isWebshellScan?: boolean;
  fileCount?: number; // 文件数量（历史记录列表中使用，避免加载所有文件）
  stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
  };
}

export interface NetworkLog {
  id: string;
  timestamp: number;
  method: string;
  url: string;
  requestHeaders: string;
  requestBody: string;
  responseStatus: number;
  responseStatusText: string;
  responseHeaders: string;
  responseBody: string;
  duration: number;
  size: number;
}
