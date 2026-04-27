/**
 * 文件 API
 */

import { apiClient } from './client';

export interface FileResponse {
  id: string;
  project_id: string;
  name: string;
  path: string;
  content: string;
  size: number;
  created_at: string;
}

export const filesApi = {
  // 获取项目文件列表 (注意：路由在 /api/projects 下)
  getProjectFiles: (projectId: string) =>
    apiClient.get<FileResponse[]>(`/api/projects/${projectId}/files`),
};
