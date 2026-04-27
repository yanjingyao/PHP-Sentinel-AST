/**
 * 项目 API
 */

import { apiClient } from './client';

export interface Project {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  file_count: number;
  last_scan_at?: string;
}

export interface CreateProjectRequest {
  name: string;
  description?: string;
}

export const projectApi = {
  // 获取所有项目
  getAll: () => apiClient.get<Project[]>('/api/projects/'),
  
  // 获取单个项目
  getById: (id: string) => apiClient.get<Project>(`/api/projects/${id}`),
  
  // 创建项目
  create: (data: CreateProjectRequest) => apiClient.post<Project>('/api/projects/', data),
  
  // 删除项目
  delete: (id: string) => apiClient.delete(`/api/projects/${id}`),
  
  // 获取项目文件树
  getFileTree: (id: string) => apiClient.get(`/api/projects/${id}/file-tree`),
  
  // 获取项目文件列表
  getFiles: (id: string) => apiClient.get(`/api/projects/${id}/files`),
  
  // 获取文件内容
  getFileContent: (projectId: string, fileId: string) => 
    apiClient.get(`/api/projects/${projectId}/files/${fileId}`),
  
  // 上传文件
  uploadFile: (projectId: string, file: File, path?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    if (path) {
      formData.append('path', path);
    }
    return apiClient.post(`/api/projects/${projectId}/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  
  // 上传 ZIP
  uploadZip: (projectId: string, file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post(`/api/projects/${projectId}/upload-zip`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
};
