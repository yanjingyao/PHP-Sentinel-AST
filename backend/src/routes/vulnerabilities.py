"""
漏洞路由 - 漏洞查询和 AI 审计
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from database import get_db
from models import Vulnerability
from schemas import (
    VulnerabilityResponse,
    AIReviewRequest,
    AIReviewResponse,
    ChatRequest,
    ChatResponse,
    ChatMessage,
)
from services.ai_service import AIService
from services.file_service import file_service
from routes.ai import get_or_create_config, get_active_profile_config, create_ai_service

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    scan_id: Optional[str] = None,
    project_id: Optional[str] = None,
    level: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """获取漏洞列表"""
    query = select(Vulnerability)

    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)
    if project_id:
        query = query.where(Vulnerability.project_id == project_id)
    if level:
        query = query.where(Vulnerability.level == level)

    query = query.order_by(Vulnerability.created_at.desc())
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()

    return [
        VulnerabilityResponse(
            id=v.id,
            type=v.type,
            level=v.level,
            line=v.line,
            file_name=v.file_name,
            snippet=v.snippet,
            description=v.description,
            source=v.source,
            sink=v.sink,
            scan_id=v.scan_id,
            project_id=v.project_id,
            file_id=v.file_id,
            created_at=v.created_at,
            ai_assessment=v.ai_assessment,
            chat_history=v.chat_history,
        )
        for v in vulnerabilities
    ]


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vulnerability_id: str, db: AsyncSession = Depends(get_db)):
    """获取单个漏洞详情"""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vulnerability_id)
    )
    v = result.scalar_one_or_none()

    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")

    return VulnerabilityResponse(
        id=v.id,
        type=v.type,
        level=v.level,
        line=v.line,
        file_name=v.file_name,
        snippet=v.snippet,
        description=v.description,
        source=v.source,
        sink=v.sink,
        scan_id=v.scan_id,
        project_id=v.project_id,
        file_id=v.file_id,
        created_at=v.created_at,
        ai_assessment=v.ai_assessment,
        chat_history=v.chat_history,
    )


@router.post("/{vulnerability_id}/ai-review", response_model=AIReviewResponse)
async def ai_review_vulnerability(
    vulnerability_id: str, request: AIReviewRequest, db: AsyncSession = Depends(get_db)
):
    """使用 AI 审计漏洞"""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vulnerability_id)
    )
    v = result.scalar_one_or_none()

    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")

    # 获取代码上下文
    code_context = await file_service.read_file(v.project_id, v.file_name) or ""

    # 加载 AI 配置
    config_model = await get_or_create_config(db)
    profile = get_active_profile_config(config_model)
    if not profile:
        raise HTTPException(status_code=400, detail="未配置 AI 服务，请先在设置中配置 AI")

    # 调用 AI 服务
    ai = create_ai_service(profile)
    review = await ai.review_vulnerability(
        {
            "id": v.id,
            "type": v.type,
            "level": v.level,
            "file_name": v.file_name,
            "line": v.line,
            "snippet": v.snippet,
        },
        code_context,
    )

    # 保存审计结果
    v.ai_assessment = review
    await db.commit()

    return AIReviewResponse(
        vulnerability_id=vulnerability_id,
        is_false_positive=review.get("is_false_positive", False),
        report=review.get("report", ""),
        poc=review.get("poc"),
        confidence=review.get("confidence"),
    )


@router.post("/{vulnerability_id}/chat", response_model=ChatResponse)
async def chat_about_vulnerability(
    vulnerability_id: str, request: ChatRequest, db: AsyncSession = Depends(get_db)
):
    """与 AI 讨论漏洞"""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vulnerability_id)
    )
    v = result.scalar_one_or_none()

    if not v:
        raise HTTPException(status_code=404, detail="漏洞不存在")

    # 获取代码上下文
    code_context = await file_service.read_file(v.project_id, v.file_name) or ""

    # 加载 AI 配置
    config_model = await get_or_create_config(db)
    profile = get_active_profile_config(config_model)
    if not profile:
        raise HTTPException(status_code=400, detail="未配置 AI 服务，请先在设置中配置 AI")

    # 构建包含漏洞上下文的系统提示
    ai_assessment = v.ai_assessment or {}
    system_prompt = f"""你是一名专业的 PHP 安全审计专家，正在分析以下漏洞：

【漏洞基本信息】
- 类型：{v.type}
- 等级：{v.level}
- 文件：{v.file_name}
- 行号：{v.line}
- 代码片段：{v.snippet}

【代码上下文】
```php
{code_context[:2000]}
```

【AI审计结论】
{ai_assessment.get('report', '暂无审计结论')}

【POC验证方法】
{ai_assessment.get('poc', '暂无POC')}

请基于以上上下文回答用户的问题。如果用户询问漏洞原理、修复方案或利用细节，请提供专业的安全建议。"""

    # 调用 AI 对话（使用 vulnerability_id 作为 session_id 维护上下文）
    ai = create_ai_service(profile)

    # 加载历史对话记录到 AI 上下文（实现多轮对话记忆）
    if v.chat_history:
        ai.load_chat_history(vulnerability_id, v.chat_history, system_prompt)

    response = await ai.chat(vulnerability_id, request.message, system_prompt if not v.chat_history else None)

    # 更新聊天历史
    new_history = (v.chat_history or []) + [
        {"role": "user", "content": request.message},
        {"role": "assistant", "content": response},
    ]
    v.chat_history = new_history
    await db.commit()

    return ChatResponse(
        vulnerability_id=vulnerability_id, response=response, chat_history=new_history
    )
