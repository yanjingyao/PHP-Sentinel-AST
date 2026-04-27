/**
 * 漏洞 API
 */

import { apiClient } from './client';

export interface Vulnerability {
  id: string;
  type: string;
  level: '严重' | '高危' | '中危' | '低危' | '提示';
  line: number;
  file_name: string;
  snippet: string;
  description: string;
  source?: string;
  sink?: string;
  scan_id: string;
  project_id: string;
  file_id?: string;
  created_at: string;
  ai_assessment?: {
    is_false_positive: boolean;
    report: string;
    poc?: string;
    confidence?: string;
  };
  chat_history?: Array<{
    role: string;
    content: string;
  }>;
}

export interface AIReviewResponse {
  vulnerability_id: string;
  is_false_positive: boolean;
  report: string;
  poc?: string;
  confidence?: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface ChatResponse {
  vulnerability_id: string;
  response: string;
  chat_history: ChatMessage[];
}

export const vulnerabilityApi = {
  // 获取漏洞列表
  getAll: (params?: { scan_id?: string; project_id?: string; level?: string }) => 
    apiClient.get<Vulnerability[]>('/api/vulnerabilities/', { params }),
  
  // 获取单个漏洞
  getById: (id: string) => apiClient.get<Vulnerability>(`/api/vulnerabilities/${id}`),
  
  // AI 审计漏洞
  aiReview: (id: string, contextLines: number = 5) => 
    apiClient.post<AIReviewResponse>(`/api/vulnerabilities/${id}/ai-review`, {
      vulnerability_id: id,
      context_lines: contextLines,
    }),
  
  // 与 AI 对话
  chat: (id: string, message: string) => 
    apiClient.post<ChatResponse>(`/api/vulnerabilities/${id}/chat`, {
      vulnerability_id: id,
      message,
    }),
};
