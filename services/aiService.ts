import { Vulnerability, ApiProviderConfig, ApiProfile } from "../types";
import { aiProxyApi } from "../frontend/src/api/ai-proxy";
import { vulnerabilityApi } from "../frontend/src/api";

export class AIService {
  /**
   * 从 localStorage 获取当前激活的 AI 配置
   */
  getActiveProfile(): ApiProfile | null {
    const saved = localStorage.getItem('phpsentinel_ai_config');
    if (saved) {
      try {
        const config: ApiProviderConfig = JSON.parse(saved);
        return config.profiles.find(p => p.id === config.activeProfileId) || null;
      } catch {
        return null;
      }
    }
    return null;
  }

  /**
   * 审计漏洞
   * 通过后端代理调用 AI 服务（避免 CORS）
   */
  async reviewVulnerability(
    vuln: Vulnerability,
    context: string
  ): Promise<{ isFalsePositive: boolean; rawReport: string; poc?: string; payload?: string; auditedAt: number }> {
    // 检查是否配置了 AI
    const profile = this.getActiveProfile();
    if (!profile) {
      throw new Error("未配置 AI 服务。请先在「引擎设置」中添加自定义 OpenAI API。");
    }

    console.log('[AIService] 使用后端代理审计漏洞:', vuln.id);
    
    try {
      // 通过后端代理调用 AI
      const result = await aiProxyApi.review(vuln, context);
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return {
        isFalsePositive: result.is_false_positive,
        rawReport: result.report,
        poc: result.poc,
        payload: result.payload,
        auditedAt: Date.now(),
      };
    } catch (error: any) {
      console.error('[AIService] 审计失败:', error);
      throw new Error(error.response?.data?.detail || error.message || "AI 审计请求失败");
    }
  }

  /**
   * AI 对话
   * 通过后端漏洞对话接口，自动保存对话历史到数据库
   */
  async chatWithAi(
    vuln: Vulnerability,
    codeContext: string,
    userMessage: string,
    history: { role: 'user' | 'model'; text: string }[]
  ): Promise<string> {
    // 检查是否配置了 AI
    const profile = this.getActiveProfile();
    if (!profile) {
      return "错误：未配置 AI 服务。请先在「引擎设置」中添加自定义 OpenAI API。";
    }

    console.log('[AIService] 使用漏洞对话接口进行对话并保存历史');

    try {
      // 使用漏洞对话接口，后端会自动保存对话历史
      const response = await vulnerabilityApi.chat(vuln.id, userMessage);
      return response.data.response;
    } catch (error: any) {
      console.error('[AIService] 对话失败:', error);
      return `错误：${error.response?.data?.detail || error.message || "AI 对话请求失败"}`;
    }
  }

  // URL 构建逻辑已移至后端统一处理
  // 前端只负责传递用户输入的原始 URL
}
