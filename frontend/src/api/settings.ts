/**
 * 设置 API
 * 存储引擎配置、AI 配置等
 */

import { apiClient } from './client';

export interface Settings {
  id?: string;
  key?: string;
  value?: any;
  config?: any;
  updated_at?: string;
}

export const settingsApi = {
  // 获取设置
  get: (key: string) => 
    apiClient.get<Settings>(`/api/settings/${key}`),
  
  // 保存设置
  set: (key: string, value: any) => 
    apiClient.post<Settings>('/api/settings/', { key, value }),
  
  // 删除设置
  delete: (key: string) => 
    apiClient.delete(`/api/settings/${key}`),
};
