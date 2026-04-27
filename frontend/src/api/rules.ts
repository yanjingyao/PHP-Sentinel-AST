/**
 * 规则 API
 * 存储自定义规则和规则状态
 */

import { apiClient } from './client';
import { Rule } from '../../../types';

export interface CustomRule extends Rule {
  id: string;
  created_at?: string;
  updated_at?: string;
}

export interface RuleState {
  rule_id: string;
  enabled: boolean;
}

export const rulesApi = {
  // 获取所有自定义规则
  getAll: () => 
    apiClient.get<CustomRule[]>('/api/rules/'),
  
  // 创建规则
  create: (rule: Omit<CustomRule, 'id' | 'created_at' | 'updated_at'>) => 
    apiClient.post<CustomRule>('/api/rules/', rule),
  
  // 更新规则
  update: (id: string, rule: Partial<CustomRule>) => 
    apiClient.put<CustomRule>(`/api/rules/${id}`, rule),
  
  // 删除规则
  delete: (id: string) => 
    apiClient.delete(`/api/rules/${id}`),
  
  // 获取规则状态
  getStates: () => 
    apiClient.get<Record<string, boolean>>('/api/rules/states'),
  
  // 保存规则状态
  saveState: (ruleId: string, enabled: boolean) => 
    apiClient.post('/api/rules/states', { rule_id: ruleId, enabled }),
};
