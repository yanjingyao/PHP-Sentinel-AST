import { FileData, RiskLevel, ScanResult, Vulnerability } from '../types';
import { projectApi, scanApi, vulnerabilityApi, filesApi } from '../frontend/src/api';
import JSZip from 'jszip';

const POLL_INTERVAL_MS = 800;
const POLL_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * Database service using REST API backend instead of IndexedDB.
 */
export const dbService = {
  async uploadFiles(projectId: string, files: FileData[]) {
    if (!files || files.length === 0) return;

    const zip = new JSZip();
    files.forEach(file => {
      const fileName = file.name.startsWith('/') ? file.name.slice(1) : file.name;
      zip.file(fileName, file.content);
    });

    const content = await zip.generateAsync({ type: 'blob' });
    const zipFile = new File([content], 'files.zip', { type: 'application/zip' });
    await projectApi.uploadZip(projectId, zipFile);
  },

  async ensureProjectAndFiles(projectName: string, isWebshellScan: boolean, files: FileData[]): Promise<string> {
    const normalizedName = isWebshellScan ? `${projectName} [WebShell]` : `${projectName} [Audit]`;

    const projectsRes = await projectApi.getAll();
    const existingProject = projectsRes.data.find((p: any) => p.name === normalizedName);

    let projectId: string;

    // 如果有同名项目且已有文件，创建新项目（添加时间戳后缀）
    if (existingProject && existingProject.file_count > 0) {
      const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
      const uniqueName = `${projectName} (${timestamp})${isWebshellScan ? ' [WebShell]' : ' [Audit]'}`;
      const createRes = await projectApi.create({
        name: uniqueName,
        description: isWebshellScan ? 'WebShell scan' : 'Security audit',
      });
      projectId = createRes.data.id;
    } else if (existingProject) {
      // 同名项目但文件为空，复用
      projectId = existingProject.id;
    } else {
      // 创建新项目
      const createRes = await projectApi.create({
        name: normalizedName,
        description: isWebshellScan ? 'WebShell scan' : 'Security audit',
      });
      projectId = createRes.data.id;
    }

    // 总是上传新文件
    if (files.length > 0) {
      await this.uploadFiles(projectId, files);
    }

    return projectId;
  },

  // 更新现有项目的文件（用于重新扫描）
  async updateProjectFiles(projectId: string, files: FileData[]): Promise<string> {
    if (files.length > 0) {
      await this.uploadFiles(projectId, files);
    }
    return projectId;
  },

  mapApiVulnerabilities(apiVulns: any[]): Vulnerability[] {
    return apiVulns.map((v: any) => ({
      id: v.id,
      type: v.type,
      level: v.level,
      line: v.line,
      fileName: v.file_name,
      snippet: v.snippet,
      description: v.description,
      source: v.source || '',
      sink: v.sink || '',
      aiAssessment: v.ai_assessment ? {
        isFalsePositive: v.ai_assessment.is_false_positive,
        rawReport: v.ai_assessment.report,
        poc: v.ai_assessment.poc,
        payload: v.ai_assessment.payload,
        auditedAt: new Date(v.created_at).getTime(),
      } : undefined,
      chatHistory: v.chat_history?.map((msg: any) => ({
        role: msg.role === 'assistant' ? 'model' : 'user',
        text: msg.content || '',
      }))
    }));
  },

  buildStats(vulnerabilities: Vulnerability[]) {
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.level === RiskLevel.CRITICAL || v.level === 'CRITICAL').length,
      high: vulnerabilities.filter(v => v.level === RiskLevel.HIGH || v.level === 'HIGH').length,
      medium: vulnerabilities.filter(v => v.level === RiskLevel.MEDIUM || v.level === 'MEDIUM').length,
      low: vulnerabilities.filter(v => v.level === RiskLevel.LOW || v.level === 'LOW').length,
      info: vulnerabilities.filter(v => v.level === RiskLevel.INFO || v.level === 'INFO').length,
    };
  },

  async runBackendScan(params: {
    files: FileData[];
    projectName: string;
    isWebshellScan: boolean;
    onProgress?: (progress: number) => void;
    existingProjectId?: string; // 传入现有项目ID则覆盖扫描
  }): Promise<ScanResult> {
    const { files, projectName, isWebshellScan, onProgress, existingProjectId } = params;

    const projectId = existingProjectId 
      ? await this.updateProjectFiles(existingProjectId, files)
      : await this.ensureProjectAndFiles(projectName, isWebshellScan, files);
    
    // 读取规则状态（内置规则的启用/禁用）
    const ruleStatesJson = localStorage.getItem('phpsentinel_rule_states');
    const ruleStates = ruleStatesJson ? JSON.parse(ruleStatesJson) : {};
    
    const createRes = await scanApi.create({
      project_id: projectId,
      is_webshell_mode: isWebshellScan,
      rule_states: ruleStates,
    });

    const scanId = createRes.data.id;
    const start = Date.now();

    while (true) {
      const scanRes = await scanApi.getById(scanId);
      const scan = scanRes.data;
      const progress = scan.total_files > 0 ? (scan.scanned_files / scan.total_files) * 100 : 0;
      onProgress?.(Math.min(99, Math.max(0, progress)));

      if (scan.status === 'completed') {
        onProgress?.(100);
        const vulnsRes = await vulnerabilityApi.getAll({ scan_id: scanId });
        const vulnerabilities = this.mapApiVulnerabilities(vulnsRes.data);
        
        // 从后端获取文件列表（确保路径与漏洞中的 file_name 一致）
        const filesRes = await filesApi.getProjectFiles(projectId);
        const projectFiles: FileData[] = filesRes.data.map((f: any) => ({
          name: f.path,  // 使用 path 作为 name，与漏洞的 file_name 格式一致
          content: f.content,
        }));
        
        return {
          id: scanId,
          projectId,
          timestamp: new Date(scan.created_at).getTime(),
          projectName,
          files: projectFiles.length > 0 ? projectFiles : files,
          vulnerabilities,
          isWebshellScan,
          stats: this.buildStats(vulnerabilities),
        };
      }

      if (scan.status === 'failed') {
        throw new Error('后端扫描任务执行失败');
      }

      if (Date.now() - start > POLL_TIMEOUT_MS) {
        throw new Error('后端扫描超时，请重试或缩小扫描范围');
      }

      await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
    }
  },

  async saveScan(scan: ScanResult): Promise<string> {
    const result = await this.runBackendScan({
      files: scan.files,
      projectName: scan.projectName,
      isWebshellScan: scan.isWebshellScan || false,
    });
    return result.projectId;
  },

  async getAllScans(): Promise<ScanResult[]> {
    try {
      const projectsRes = await projectApi.getAll();
      const scans: ScanResult[] = [];

      for (const project of projectsRes.data) {
        const projectScansRes = await scanApi.getByProjectId(project.id);
        const projectScans = projectScansRes.data;

        if (projectScans.length === 0) continue;

        for (const scanRecord of projectScans) {
          const vulnsRes = await vulnerabilityApi.getAll({ scan_id: scanRecord.id });
          const vulnerabilities = this.mapApiVulnerabilities(vulnsRes.data);

          const originalProjectName = project.name
            .replace(/ \[WebShell\]$/, '')
            .replace(/ \[Audit\]$/, '');

          scans.push({
            id: scanRecord.id,
            projectId: project.id,
            timestamp: new Date(scanRecord.created_at).getTime(),
            projectName: originalProjectName,
            files: [],
            fileCount: project.file_count,
            vulnerabilities,
            isWebshellScan: scanRecord.is_webshell_mode,
            stats: this.buildStats(vulnerabilities),
          });
        }
      }

      return scans.sort((a, b) => b.timestamp - a.timestamp);
    } catch (error) {
      console.error('Failed to load scans:', error);
      return [];
    }
  },

  async loadScanFiles(projectId: string): Promise<FileData[]> {
    try {
      const filesRes = await projectApi.getFiles(projectId);
      return filesRes.data.map((f: any) => ({
        name: f.path,
        content: f.content,
      }));
    } catch (error) {
      console.error('Failed to load scan files:', error);
      return [];
    }
  },

  async getGlobalVerifiedVulnerabilities(): Promise<(Vulnerability & { projectName: string })[]> {
    try {
      const allScans = await this.getAllScans();
      const results: (Vulnerability & { projectName: string })[] = [];

      allScans.forEach(scan => {
        scan.vulnerabilities.forEach(vuln => {
          if (vuln.verificationEvidence) {
            results.push({
              ...vuln,
              projectName: scan.projectName,
            });
          }
        });
      });

      return results.sort((a, b) => (b.aiAssessment?.auditedAt || 0) - (a.aiAssessment?.auditedAt || 0));
    } catch (error) {
      console.error('Failed to get verified vulnerabilities:', error);
      return [];
    }
  },

  async deleteScan(scanId: string, projectId: string): Promise<void> {
    try {
      const projectScansRes = await scanApi.getByProjectId(projectId);
      const projectScans = projectScansRes.data;

      await scanApi.delete(scanId);

      if (projectScans.length <= 1) {
        await projectApi.delete(projectId);
      }
    } catch (error) {
      console.error('Failed to delete scan:', error);
      throw error;
    }
  },

  open(): Promise<any> {
    return Promise.resolve({});
  },
};
