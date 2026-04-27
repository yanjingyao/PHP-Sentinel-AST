from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "SQL 注入"
    XSS = "跨站脚本攻击 (XSS)"
    CODE_EXECUTION = "远程代码执行 (RCE)"
    FILE_INCLUSION = "文件包含 (LFI/RFI)"
    SENSITIVE_CALL = "敏感函数调用"
    SSRF = "服务端请求伪造 (SSRF)"
    DESERIALIZATION = "不安全的反序列化"
    PATH_TRAVERSAL = "路径穿越/任意文件操作"
    FILE_UPLOAD = "不安全的文件上传"
    WEAK_CRYPTO = "弱加密/哈希算法"
    HEADER_INJECTION = "HTTP 头部注入"
    LDAP_INJECTION = "LDAP 注入"
    WEBSHELL = "Webshell 恶意后门"
    CUSTOM = "自定义规则"


class RiskLevel(str, Enum):
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "提示"


# File Schemas
class FileCreate(BaseModel):
    name: str
    path: str
    content: str
    size: int = 0


class FileResponse(BaseModel):
    id: str
    project_id: str
    name: str
    path: str
    content: str
    size: int
    created_at: datetime

    class Config:
        from_attributes = True


class FileTreeNode(BaseModel):
    name: str
    path: str
    type: str  # file or directory
    children: Optional[List["FileTreeNode"]] = None
    size: Optional[int] = None


# Project Schemas
class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    file_count: Optional[int] = 0
    last_scan_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ProjectDetailResponse(ProjectResponse):
    files: List[FileResponse]
    file_tree: Optional[List[FileTreeNode]] = None


# Scan Schemas
class VulnerabilityCreate(BaseModel):
    id: Optional[str] = None
    type: str
    level: str
    line: int
    file_name: str
    snippet: str
    description: str
    source: Optional[str] = None
    sink: Optional[str] = None


class ScanCreate(BaseModel):
    project_id: str
    is_webshell_mode: bool = False
    vulnerabilities: Optional[List[VulnerabilityCreate]] = None
    rule_states: Optional[Dict[str, bool]] = None  # 规则启用状态（用于内置规则）


class ScanProgress(BaseModel):
    scan_id: str
    status: str  # pending, running, completed, failed
    total_files: int
    scanned_files: int
    progress_percentage: float
    current_file: Optional[str] = None
    vulnerabilities_found: int = 0


class ScanResponse(BaseModel):
    id: str
    project_id: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_files: int
    scanned_files: int
    is_webshell_mode: bool
    created_at: datetime
    vulnerability_count: Optional[int] = 0

    class Config:
        from_attributes = True


# Vulnerability Schemas
class VulnerabilityBase(BaseModel):
    type: VulnerabilityType
    level: RiskLevel
    line: int
    file_name: str
    snippet: str
    description: str
    source: Optional[str] = None
    sink: Optional[str] = None


class VulnerabilityCreate(VulnerabilityBase):
    scan_id: str
    project_id: str
    file_id: Optional[str] = None


class VulnerabilityResponse(VulnerabilityBase):
    id: str
    scan_id: str
    project_id: str
    file_id: Optional[str]
    created_at: datetime
    ai_assessment: Optional[Dict[str, Any]] = None
    chat_history: Optional[List[Dict[str, str]]] = None

    class Config:
        from_attributes = True


class VulnerabilityStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


# AI Review Schemas
class AIReviewRequest(BaseModel):
    vulnerability_id: str
    context_lines: int = 5


class AIReviewResponse(BaseModel):
    vulnerability_id: str
    is_false_positive: bool
    report: str
    poc: Optional[str] = None
    confidence: Optional[str] = None


class ChatMessage(BaseModel):
    role: str  # user or assistant
    content: str


class ChatRequest(BaseModel):
    vulnerability_id: str
    message: str


class ChatResponse(BaseModel):
    vulnerability_id: str
    response: str
    chat_history: List[ChatMessage]


# AI Config Schemas
class AIConfigBase(BaseModel):
    provider_type: str = "gemini"  # gemini, openai, moonshot
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: str = "gemini-pro"


class AIConfigUpdate(AIConfigBase):
    pass


class AIConfigResponse(AIConfigBase):
    id: str
    updated_at: datetime

    class Config:
        from_attributes = True


# Network Log Schemas
class NetworkLogBase(BaseModel):
    method: str
    url: str
    request_headers: Optional[str] = None
    request_body: Optional[str] = None
    response_status: int
    response_status_text: str
    response_headers: Optional[str] = None
    response_body: Optional[str] = None
    duration: int
    size: int


class NetworkLogCreate(NetworkLogBase):
    pass


class NetworkLogResponse(NetworkLogBase):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True


# Proxy Request Schema
class ProxyRequest(BaseModel):
    method: str
    url: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    timeout: int = 10  # 默认超时 10 秒


class ProxyResponse(BaseModel):
    status: int
    status_text: str
    headers: Dict[str, str]
    body: str
    time: int
    size: int



# Rule Schemas
class RuleBase(BaseModel):
    name: str
    pattern: str
    type: VulnerabilityType
    level: RiskLevel
    enabled: bool = True
    description: Optional[str] = None


class RuleCreate(RuleBase):
    is_built_in: bool = False


class RuleResponse(RuleBase):
    id: str
    is_built_in: bool
    created_at: datetime

    class Config:
        from_attributes = True


class RuleStateUpdate(BaseModel):
    rule_id: str
    enabled: bool


# Network Log Schemas
class NetworkLogCreate(BaseModel):
    method: str
    url: str
    request_headers: Optional[str] = None
    request_body: Optional[str] = None
    response_status: int = 0
    response_status_text: Optional[str] = None
    response_headers: Optional[str] = None
    response_body: Optional[str] = None
    duration: int = 0
    size: int = 0


class NetworkLogResponse(BaseModel):
    id: str
    method: str
    url: str
    request_headers: Optional[str]
    request_body: Optional[str]
    response_status: int
    response_status_text: Optional[str]
    response_headers: Optional[str]
    response_body: Optional[str]
    duration: int
    size: int
    created_at: datetime

    class Config:
        from_attributes = True


# Dashboard Stats
class DashboardStats(BaseModel):
    total_projects: int
    total_scans: int
    total_vulnerabilities: int
    vulnerabilities_by_level: Dict[str, int]
    vulnerabilities_by_type: Dict[str, int]
    recent_scans: List[ScanResponse]
    recent_vulnerabilities: List[VulnerabilityResponse]
