"""
AI 服务 - 处理 AI 审计和对话
支持多种 AI 提供商：Gemini、OpenAI、Moonshot
改进版：更好的响应解析、错误处理和上下文管理
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List

import httpx

# 创建 logger 实例
logger = logging.getLogger(__name__)


class AIProvider(str, Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    MOONSHOT = "moonshot"


@dataclass
class AIConfig:
    provider: AIProvider = AIProvider.GEMINI
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: str = "gemini-pro"
    timeout: float = 60.0
    max_retries: int = 3


@dataclass
class AIReviewResult:
    """AI 审计结果"""

    is_false_positive: bool = False
    report: str = ""
    poc: Optional[str] = None  # 验证方法 (curl/httpie)
    payload: Optional[str] = None  # 攻击载荷 (SQL/XSS/RCE)
    confidence: str = "medium"  # high, medium, low
    raw_response: str = ""
    error: Optional[str] = None


@dataclass
class ChatContext:
    """对话上下文"""

    messages: List[Dict[str, str]] = field(default_factory=list)
    max_history: int = 20

    def add_message(self, role: str, content: str):
        """添加消息到上下文"""
        self.messages.append({"role": role, "content": content})
        # 保留最近的 max_history 条消息
        if len(self.messages) > self.max_history:
            # 保留 system message 和最近的消息
            system_msgs = [m for m in self.messages if m["role"] == "system"]
            other_msgs = [m for m in self.messages if m["role"] != "system"]
            self.messages = (
                system_msgs + other_msgs[-(self.max_history - len(system_msgs)) :]
            )

    def get_messages(self) -> List[Dict[str, str]]:
        """获取所有消息"""
        return self.messages.copy()

    def clear(self):
        """清空上下文"""
        self.messages.clear()


class AIService:
    """AI 服务 - 漏洞审计和对话"""

    SYSTEM_PROMPT_REVIEW = """你是一名专业的 PHP 安全审计专家，具有丰富的代码审计和渗透测试经验。

你的任务是分析提供的 PHP 代码漏洞，并给出专业的安全评估。

【极其重要】必须严格区分 poc 和 payload 两个字段：

- poc: 必须提供一个完整的 HTTP 请求报文格式，包含请求行、Host、User-Agent、Content-Type 等关键头部，模拟真实的攻击请求。请使用标准 HTTP 协议格式。
- payload: 纯攻击载荷本身，不包含任何 URL、协议头或命令包装。这是攻击的核心字符串。

示例 1 (SQL注入):
{
    "is_false_positive": false,
    "confidence": "high",
    "analysis": "存在SQL注入漏洞，用户输入直接拼接到SQL语句",
    "poc": "POST /login.php HTTP/1.1\\nHost: target.com\\nContent-Type: application/x-www-form-urlencoded\\n\\nusername=admin' OR '1'='1&password=xxx",
    "payload": "' OR '1'='1' -- ",
    "recommendations": "使用预处理语句"
}

示例 2 (RCE漏洞):
{
    "is_false_positive": false,
    "confidence": "high",
    "analysis": "存在命令执行漏洞，未过滤的用户输入直接传入 system 函数",
    "poc": "GET /vuln.php?cmd=whoami HTTP/1.1\\nHost: 127.0.0.1:8080\\nUser-Agent: Mozilla/5.0\\nAccept: */*\\n\\n",
    "payload": "whoami",
    "recommendations": "使用 escapeshellarg 或禁用危险函数"
}

请严格按照以下 JSON 格式回复，不要添加任何其他文本：
{
    "is_false_positive": false,
    "confidence": "high",
    "analysis": "漏洞分析...",
    "poc": "完整的 HTTP 请求报文 (String format)",
    "payload": "纯攻击载荷字符串，不含URL",
    "recommendations": "修复建议..."
}

字段说明：
- is_false_positive: 如果是误报设为 true，真实漏洞设为 false
- confidence: 根据证据充分程度设为 "high"、"medium" 或 "low"
- analysis: 详细说明漏洞原理、危害程度、利用条件
- poc: 必须是完整的 HTTP 请求报文格式（类似 Burp Suite 的 Raw 请求），包含请求方法、路径、HTTP版本、Host、Headers 和 Body。如果不知道具体 Host，可使用 127.0.0.1:8080。
- payload: 纯攻击载荷，是poc中参数的值。示例: "' OR '1'='1" 或 "<script>alert(1)</script>"
- recommendations: 提供具体的修复方案和代码示例

核心区别：
- poc = 完整的 HTTP 协议交互报文
- payload = 攻击字符串本身

如果无法确定URL，poc可以用占位符路径，但格式必须符合 HTTP 协议规范。"""

    SYSTEM_PROMPT_CHAT = """你是一名专业的 PHP 安全专家，正在帮助用户分析安全漏洞。
请提供专业、准确、实用的安全建议。如果用户询问技术细节，请给出清晰的解释和示例代码。
保持友好但专业的态度，回答要简洁明了。"""

    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self.client = httpx.AsyncClient(timeout=self.config.timeout)
        self._chat_contexts: Dict[str, ChatContext] = {}  # 存储多轮对话上下文

    def update_config(self, config: AIConfig):
        """更新 AI 配置"""
        self.config = config

    async def review_vulnerability(
        self, vulnerability: Dict[str, Any], code_context: str, retry_count: int = 0
    ) -> AIReviewResult:
        """
        审计漏洞

        Args:
            vulnerability: 漏洞信息
            code_context: 代码上下文
            retry_count: 当前重试次数
        """
        prompt = self._build_review_prompt(vulnerability, code_context)

        try:
            if self.config.provider == AIProvider.GEMINI:
                response_text = await self._call_gemini(prompt, is_chat=False)
            elif self.config.provider == AIProvider.OPENAI:
                response_text = await self._call_openai(prompt, is_chat=False)
            elif self.config.provider == AIProvider.MOONSHOT:
                response_text = await self._call_moonshot(prompt, is_chat=False)
            else:
                return self._error_result(f"不支持的 AI 提供商: {self.config.provider}")

            return self._parse_review_response(response_text)

        except httpx.TimeoutException:
            if retry_count < self.config.max_retries:
                return await self.review_vulnerability(
                    vulnerability, code_context, retry_count + 1
                )
            return self._error_result("AI 服务请求超时，请稍后重试")

        except httpx.HTTPStatusError as e:
            error_msg = self._parse_http_error(e)
            return self._error_result(error_msg)

        except Exception as e:
            return self._error_result(f"AI 审计失败: {str(e)}")

    async def chat(
        self, session_id: str, message: str, system_prompt: Optional[str] = None
    ) -> str:
        """
        对话功能

        Args:
            session_id: 会话 ID，用于维护上下文
            message: 用户消息
            system_prompt: 可选的自定义系统提示
        """
        # 获取或创建上下文
        if session_id not in self._chat_contexts:
            self._chat_contexts[session_id] = ChatContext()
            # 添加系统提示
            self._chat_contexts[session_id].add_message(
                "system", system_prompt or self.SYSTEM_PROMPT_CHAT
            )

        context = self._chat_contexts[session_id]
        context.add_message("user", message)

        try:
            if self.config.provider == AIProvider.GEMINI:
                response = await self._chat_gemini(context.get_messages())
            elif self.config.provider == AIProvider.OPENAI:
                response = await self._chat_openai(context.get_messages())
            elif self.config.provider == AIProvider.MOONSHOT:
                response = await self._chat_moonshot(context.get_messages())
            else:
                response = "抱歉，AI 服务暂时不可用。"

            # 保存助手回复到上下文
            context.add_message("assistant", response)
            return response

        except Exception as e:
            return f"对话失败：{str(e)}"

    def clear_chat_context(self, session_id: str):
        """清空指定会话的上下文"""
        if session_id in self._chat_contexts:
            self._chat_contexts[session_id].clear()
            del self._chat_contexts[session_id]

    def load_chat_history(self, session_id: str, chat_history: List[Dict[str, str]], system_prompt: Optional[str] = None):
        """从数据库加载历史对话记录到上下文"""
        # 创建新的上下文
        self._chat_contexts[session_id] = ChatContext()
        context = self._chat_contexts[session_id]
        
        # 添加系统提示
        if system_prompt:
            context.add_message("system", system_prompt)
        
        # 加载历史记录
        for msg in chat_history:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            # 跳过 system 消息（已单独添加）
            if role == "system":
                continue
            
            # OpenAI API 只接受 user/assistant/system 角色
            # 将 model 映射回 assistant
            if role == "model":
                role = "assistant"
            
            context.add_message(role, content)

    def _build_review_prompt(
        self, vulnerability: Dict[str, Any], code_context: str
    ) -> str:
        """构建审计提示"""
        return f"""请审计以下 PHP 代码漏洞：

【漏洞信息】
- 类型：{vulnerability.get("type", "Unknown")}
- 等级：{vulnerability.get("level", "Unknown")}
- 文件：{vulnerability.get("file_name", "Unknown")}
- 行号：{vulnerability.get("line", 0)}
- 描述：{vulnerability.get("description", "No description")}

【问题代码片段】
```php
{vulnerability.get("snippet", "")}
```

【上下文代码】
```php
{code_context}
```

【污点追踪】
- 污染源：{vulnerability.get("source", "Unknown")}
- 汇聚点：{vulnerability.get("sink", "Unknown")}

请按照系统提示中的 JSON 格式返回审计结果。"""

    def _parse_review_response(self, text: str) -> AIReviewResult:
        """解析 AI 审计响应"""
        try:
            # 尝试提取 JSON
            json_match = re.search(r"\{[\s\S]*\}", text)
            if json_match:
                data = json.loads(json_match.group())

                return AIReviewResult(
                    is_false_positive=data.get("is_false_positive", False),
                    report=data.get("analysis", text),
                    poc=data.get("poc"),
                    payload=data.get("payload"),
                    confidence=data.get("confidence", "medium"),
                    raw_response=text,
                )
        except json.JSONDecodeError:
            pass

        # 回退到启发式解析
        is_fp = self._detect_false_positive(text)
        confidence = self._extract_confidence(text)
        poc = self._extract_poc(text)
        payload = self._extract_payload(text)

        return AIReviewResult(
            is_false_positive=is_fp,
            report=text,
            poc=poc,
            payload=payload,
            confidence=confidence,
            raw_response=text,
        )

    def _detect_false_positive(self, text: str) -> bool:
        """检测是否为误报"""
        fp_indicators = ["误报", "false positive", "不是漏洞", "无法利用", "安全的"]
        real_indicators = ["真实漏洞", "确认漏洞", "可利用", "存在风险", "高危"]

        text_lower = text.lower()
        fp_score = sum(1 for ind in fp_indicators if ind in text_lower)
        real_score = sum(1 for ind in real_indicators if ind in text_lower)

        return fp_score > real_score

    def _extract_confidence(self, text: str) -> str:
        """提取置信度"""
        text_lower = text.lower()
        if any(
            w in text_lower
            for w in ["确定", "肯定", "明确", "毫无疑问", "high confidence"]
        ):
            return "high"
        elif any(
            w in text_lower
            for w in ["可能", "大概", "或许", "不确定", "low confidence"]
        ):
            return "low"
        return "medium"

    def _extract_poc(self, text: str) -> Optional[str]:
        """从文本中提取 POC"""
        # 查找代码块
        code_blocks = re.findall(
            r"```(?:php|bash|curl|http)?\n(.*?)\n```", text, re.DOTALL
        )
        if code_blocks:
            # 返回第一个非空的代码块
            for block in code_blocks:
                if block.strip():
                    return block.strip()
        return None

    def _extract_payload(self, text: str) -> Optional[str]:
        """从文本中提取 Payload"""
        # 尝试查找 Payload/PoC 标签后的代码
        payload_patterns = [
            r'payload[":\s]+["\']?([^"\'\n]+)',
            r'Payload[":\s]+["\']?([^"\'\n]+)',
            r'攻击载荷[":\s]+["\']?([^"\'\n]+)',
        ]

        for pattern in payload_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                payload = match.group(1).strip()
                if payload and payload not in ["null", "none", ""]:
                    return payload

        # 查找代码块中看起来像攻击载荷的内容
        code_blocks = re.findall(r"```(?:php|sql|bash)?\n(.*?)\n```", text, re.DOTALL)
        for block in code_blocks:
            block = block.strip()
            # 如果包含常见的攻击特征，可能是 payload
            if any(
                char in block
                for char in ["'", '"', "<", ">", "OR", "AND", ";", "|", "`"]
            ):
                if len(block) < 200:  # payload 通常比较短
                    return block

        return None

    def _parse_http_error(self, error: httpx.HTTPStatusError) -> str:
        """解析 HTTP 错误"""
        status_code = error.response.status_code

        error_messages = {
            401: "API 密钥无效或已过期，请检查配置",
            403: "API 密钥没有权限访问此资源",
            429: "请求过于频繁，请稍后重试",
            500: "AI 服务内部错误，请稍后重试",
            502: "AI 服务暂时不可用，请稍后重试",
            503: "AI 服务过载，请稍后重试",
        }

        return error_messages.get(status_code, f"AI 服务错误 (HTTP {status_code})")

    def _error_result(self, error_msg: str) -> AIReviewResult:
        """创建错误结果"""
        return AIReviewResult(
            is_false_positive=False,
            report=error_msg,
            poc=None,
            confidence="none",
            error=error_msg,
        )

    # ========== API 调用方法 ==========

    async def _call_gemini(self, prompt: str, is_chat: bool = False) -> str:
        """调用 Gemini API"""
        api_key = self.config.api_key or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("Gemini API 密钥未配置")

        model_name = self.config.model if self.config.model else "gemini-1.5-pro"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"

        system_prompt = (
            self.SYSTEM_PROMPT_CHAT if is_chat else self.SYSTEM_PROMPT_REVIEW
        )

        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2 if not is_chat else 0.7,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json" if not is_chat else "text/plain",
            },
        }

        response = await self.client.post(url, params={"key": api_key}, json=payload)
        response.raise_for_status()

        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]

    async def _call_openai(self, prompt: str, is_chat: bool = False) -> str:
        """调用 OpenAI API"""
        api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API 密钥未配置")

        # 使用 URL 构建方法处理 base_url
        url = self._build_api_url(
            self.config.base_url or "https://api.openai.com/v1/chat/completions"
        )
        if not url:
            raise ValueError("API Base URL 格式无效或为空")

        logger.debug(f"OpenAI API URL: {url}")

        payload = {
            "model": self.config.model or "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": self.SYSTEM_PROMPT_CHAT
                    if is_chat
                    else self.SYSTEM_PROMPT_REVIEW,
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2 if not is_chat else 0.7,
            "max_tokens": 2048,
        }

        response = await self.client.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()

        result = response.json()
        # 检查响应格式是否正确
        if "choices" not in result or not result["choices"]:
            logger.error(f"AI API 响应格式错误: {result}")
            raise ValueError(f"AI API 响应格式错误: 缺少 'choices' 字段")
        return result["choices"][0]["message"]["content"]

    async def _call_moonshot(self, prompt: str, is_chat: bool = False) -> str:
        """调用 Moonshot (Kimi) API"""
        api_key = self.config.api_key or os.getenv("MOONSHOT_API_KEY")
        if not api_key:
            raise ValueError("Moonshot API 密钥未配置")

        # 使用 URL 构建方法智能补全路径
        url = self._build_api_url(self.config.base_url or "https://api.moonshot.cn")
        if not url:
            raise ValueError("API Base URL 格式无效或为空")

        logger.debug(f"Moonshot API URL: {url}")
        logger.debug(f"Moonshot Model: {self.config.model or 'kimi-k2.5'}")

        payload = {
            "model": self.config.model or "kimi-k2.5",
            "messages": [
                {
                    "role": "system",
                    "content": self.SYSTEM_PROMPT_CHAT
                    if is_chat
                    else self.SYSTEM_PROMPT_REVIEW,
                },
                {"role": "user", "content": prompt},
            ],
            # 注意：不设置 temperature 和 max_tokens，因为某些 API（如 Moonshot）只支持默认值
        }

        response = await self.client.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()

        return response.json()["choices"][0]["message"]["content"]

    async def _chat_gemini(self, messages: List[Dict[str, str]]) -> str:
        """使用 Gemini 进行多轮对话"""
        # Gemini 的对话格式转换
        api_key = self.config.api_key or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("Gemini API 密钥未配置")

        model_name = self.config.model if self.config.model else "gemini-1.5-pro"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"

        # 转换消息格式
        contents = []
        for msg in messages:
            if msg["role"] != "system":  # Gemini 不支持 system role
                role = "user" if msg["role"] == "user" else "model"
                contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        # 获取 system prompt
        system_msg = next((m for m in messages if m["role"] == "system"), None)

        payload = {
            "contents": contents,
            "generationConfig": {"temperature": 0.7, "maxOutputTokens": 1024},
        }

        if system_msg:
            payload["systemInstruction"] = {"parts": [{"text": system_msg["content"]}]}

        response = await self.client.post(url, params={"key": api_key}, json=payload)
        response.raise_for_status()

        return response.json()["candidates"][0]["content"]["parts"][0]["text"]

    async def _chat_openai(self, messages: List[Dict[str, str]]) -> str:
        """使用 OpenAI 进行多轮对话"""
        api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API 密钥未配置")

        url = self._build_api_url(
            self.config.base_url or "https://api.openai.com/v1/chat/completions"
        )
        if not url:
            raise ValueError("API Base URL 格式无效或为空")

        payload = {
            "model": self.config.model or "gpt-4",
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 1024,
        }

        response = await self.client.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()

        return response.json()["choices"][0]["message"]["content"]

    async def _chat_moonshot(self, messages: List[Dict[str, str]]) -> str:
        """使用 Moonshot 进行多轮对话"""
        api_key = self.config.api_key or os.getenv("MOONSHOT_API_KEY")
        if not api_key:
            raise ValueError("Moonshot API 密钥未配置")

        # 使用 URL 构建方法智能补全路径
        url = self._build_api_url(self.config.base_url or "https://api.moonshot.cn")
        if not url:
            raise ValueError("API Base URL 格式无效或为空")

        payload = {
            "model": self.config.model or "kimi-k2.5",
            "messages": messages,
            # 注意：不设置 temperature 和 max_tokens，因为某些 API（如 Moonshot）只支持默认值
        }

        response = await self.client.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()

        return response.json()["choices"][0]["message"]["content"]

    def _build_api_url(self, base_url: str) -> str:
        """构建 API URL - 使用用户提供的完整路径"""
        url = base_url.strip()
        if not url or url in ["/", "http://", "https://"]:
            return ""

        # 移除末尾斜杠
        url = url.rstrip("/")

        # 补充协议
        if not url.startswith("http"):
            url = "https://" + url

        # 完全使用用户提供的 URL，不添加任何路径
        return url

    async def close(self):
        """关闭 HTTP 客户端"""
        await self.client.aclose()


# 全局实例
ai_service = AIService()
