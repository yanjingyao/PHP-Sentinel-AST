/**
 * 网络日志 API
 * 存储 HTTP Proxy History
 */

import { apiClient } from './client';
import { NetworkLog } from '../../../types';

export interface NetworkLogEntry {
  id: string;
  method: string;
  url: string;
  request_headers: string;
  request_body: string;
  response_status: number;
  response_status_text: string;
  response_headers: string;
  response_body: string;
  duration: number;
  size: number;
  created_at: string;
}

export const networkApi = {
  // 获取所有网络日志
  getAll: (limit: number = 50) => 
    apiClient.get<NetworkLogEntry[]>('/api/network/logs', { params: { limit } }),
  
  // 创建日志
  create: (log: Omit<NetworkLog, 'id' | 'timestamp'>) => 
    apiClient.post<NetworkLogEntry>('/api/network/logs', {
      method: log.method,
      url: log.url,
      request_headers: log.requestHeaders,
      request_body: log.requestBody,
      response_status: log.responseStatus,
      response_status_text: log.responseStatusText,
      response_headers: log.responseHeaders,
      response_body: log.responseBody,
      duration: log.duration,
      size: log.size,
    }),
  
  // 删除日志
  delete: (id: string) => 
    apiClient.delete(`/api/network/logs/${id}`),
  
  // 清空所有日志
  clearAll: () => 
    apiClient.delete('/api/network/logs'),

  // Proxy Request
  proxy: (data: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  }) => apiClient.post('/api/network/proxy', data),
};
