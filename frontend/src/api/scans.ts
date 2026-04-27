/**
 * 扫描 API
 */

import { apiClient } from './client';

export interface Scan {
  id: string;
  project_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  total_files: number;
  scanned_files: number;
  is_webshell_mode: boolean;
  created_at: string;
  vulnerability_count: number;
}

export interface ScanProgress {
  scan_id: string;
  status: string;
  total_files: number;
  scanned_files: number;
  progress_percentage: number;
  current_file?: string;
  vulnerabilities_found: number;
}

export interface CreateScanRequest {
  project_id: string;
  is_webshell_mode?: boolean;
  vulnerabilities?: Array<{
    id: string;
    type: string;
    level: string;
    line: number;
    file_name: string;
    snippet: string;
    description: string;
    source?: string;
    sink?: string;
  }>;
  rule_states?: Record<string, boolean>;  // 规则启用状态（用于内置规则）
}

export const scanApi = {
  // 创建扫描任务
  create: (data: CreateScanRequest) => apiClient.post<Scan>('/api/scans/', data),

  // 获取扫描详情
  getById: (id: string) => apiClient.get<Scan>(`/api/scans/${id}`),

  // 获取项目的所有扫描记录
  getByProjectId: (projectId: string) => apiClient.get<Scan[]>(`/api/scans/project/${projectId}`),

  // 删除单个扫描记录
  delete: (id: string) => apiClient.delete(`/api/scans/${id}`),
};
