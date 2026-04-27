/**
 * AI API 代理
 * 前端通过后端代理调用 AI 服务（避免 CORS 问题）
 */

import { apiClient } from './client';
import { Vulnerability } from '../../../types';

export interface AIReviewRequest {
  vulnerability: {
    type: string;
    level: string;
    fileName: string;
    line: number;
    description: string;
    snippet: string;
    source: string;
    sink: string;
  };
  code_context: string;
}

export interface AIReviewResponse {
  is_false_positive: boolean;
  report: string;
  poc?: string;
  payload?: string;
  confidence: string;
  error?: string;
}

export interface AIChatRequest {
  messages: Array<{
    role: 'system' | 'user' | 'assistant';
    content: string;
  }>;
}

export interface AIChatResponse {
  response: string;
}

export interface TestProfileRequest {
  id: string;
  name: string;
  type: string;
  apiKey: string;
  baseUrl: string;
  modelName: string;
}

export const aiProxyApi = {
  /**
   * 审计漏洞（通过后端代理）
   * 会自动保存审计结果到数据库
   */
  review: async (vuln: Vulnerability, codeContext: string): Promise<AIReviewResponse> => {
    const response = await apiClient.post<AIReviewResponse>('/api/ai/review', {
      vulnerability_id: vuln.id,
      vulnerability: {
        type: vuln.type,
        level: vuln.level,
        file_name: vuln.fileName,
        line: vuln.line,
        description: vuln.description,
        snippet: vuln.snippet,
        source: vuln.source,
        sink: vuln.sink,
      },
      code_context: codeContext,
    });
    return response.data;
  },

  /**
   * 对话聊天（通过后端代理）
   */
  chat: async (messages: Array<{ role: string; content: string }>): Promise<string> => {
    const response = await apiClient.post<AIChatResponse>('/api/ai/chat', {
      messages,
    });
    return response.data.response;
  },

  /**
   * 测试 AI 连接（使用临时配置，不保存到数据库）
   */
  testConnectionWithProfile: async (profile: TestProfileRequest): Promise<{ status: string; message: string }> => {
    const response = await apiClient.post<{ status: string; message: string }>('/api/ai/test-profile', { profile });
    return response.data;
  },
};
