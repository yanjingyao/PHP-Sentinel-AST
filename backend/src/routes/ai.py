"""
AI 代理路由
前端通过此接口调用 AI 服务，后端代理请求（避免 CORS）
"""

import logging
import os
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from models import AIConfig as AIConfigModel, Vulnerability
from services.ai_service import AIService, AIConfig, AIProvider

# 创建 logger 实例
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai"])


async def get_or_create_config(db: AsyncSession) -> AIConfigModel:
    """获取或创建默认 AI 配置"""
    result = await db.execute(
        select(AIConfigModel).where(AIConfigModel.id == "default")
    )
    config = result.scalar_one_or_none()

    if not config:
        config = AIConfigModel(
            id="default", config={"activeProfileId": "", "profiles": []}
        )
        db.add(config)
        await db.commit()
        await db.refresh(config)

    return config


def get_active_profile_config(config_model: AIConfigModel) -> Optional[Dict[str, Any]]:
    """从配置模型中获取当前激活的 profile 配置"""
    if not config_model.config:
        logger.warning("No config in model")
        return None

    config_data = config_model.config
    # 尝试解析 JSON 字符串（如果是字符串的话）
    if isinstance(config_data, str):
        import json

        try:
            config_data = json.loads(config_data)
        except json.JSONDecodeError:
            logger.error("Failed to decode JSON config string")
            return None

    active_profile_id = config_data.get("activeProfileId")
    profiles = config_data.get("profiles", [])

    if not active_profile_id or not profiles:
        logger.warning(f"Missing activeProfileId ({active_profile_id}) or profiles")
        return None

    # 查找激活的 profile
    for profile in profiles:
        if profile.get("id") == active_profile_id:
            return profile

    logger.warning(f"Active profile {active_profile_id} not found in profiles")
    return None


def create_ai_service(profile: Dict[str, Any]) -> AIService:
    """根据 profile 配置创建 AI 服务"""
    profile_type = profile.get("type", "custom-openai")
    api_key = profile.get("apiKey") or profile.get("api_key")
    base_url = profile.get("baseUrl") or profile.get("base_url")
    model_name = profile.get("modelName") or profile.get("model_name") or "gpt-4o"

    # 处理 base_url: 只移除末尾斜杠，其他保持不变
    if base_url and base_url.endswith("/"):
        base_url = base_url[:-1]

    # 确定 provider 类型
    if profile_type == "gemini-builtin":
        provider = AIProvider.GEMINI
    elif "moonshot" in (base_url or "").lower():
        provider = AIProvider.MOONSHOT
    elif "gemini" in (base_url or "").lower():
        provider = AIProvider.GEMINI
    else:
        provider = AIProvider.OPENAI

    # Debug: Log configured values
    logger.debug("Creating AI Service:")
    logger.debug(f"  Profile Type: {profile_type}")
    logger.debug(f"  Provider: {provider}")
    logger.debug(f"  BaseURL: {base_url}")
    logger.debug(f"  Model: {model_name}")
    logger.debug(f"  API Key exists: {bool(api_key)}")
    if api_key:
        logger.debug(f"  API Key (first 10 chars): {api_key[:10]}...")

    ai_config = AIConfig(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model_name,
    )

    return AIService(ai_config)


@router.post("/chat")
async def ai_chat(request: dict, db: AsyncSession = Depends(get_db)):
    """
    代理 AI 对话请求
    前端调用此接口，后端再去调用实际的 AI 服务（避免 CORS）
    """
    config_model = await get_or_create_config(db)
    profile = get_active_profile_config(config_model)

    if not profile:
        raise HTTPException(
            status_code=400, detail="未配置 AI 服务。请先在「引擎设置」中配置 API。"
        )

    try:
        ai = create_ai_service(profile)

        messages = request.get("messages", [])
        if messages:
            # 找到最后一条用户消息
            user_messages = [m for m in messages if m.get("role") == "user"]
            if user_messages:
                last_message = user_messages[-1].get("content", "")
                response = await ai.chat(session_id="api_chat", message=last_message)
                return {"response": response}

        raise HTTPException(status_code=400, detail="消息格式错误")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 请求失败: {str(e)}")


@router.post("/review")
async def ai_review(request: dict, db: AsyncSession = Depends(get_db)):
    """
    代理 AI 审计请求
    用于漏洞审计，前端调用此接口，后端再去调用实际的 AI 服务
    如果提供了 vulnerability_id，会自动保存审计结果到数据库
    """
    config_model = await get_or_create_config(db)
    profile = get_active_profile_config(config_model)

    if not profile:
        raise HTTPException(
            status_code=400, detail="未配置 AI 服务。请先在「引擎设置」中配置 API。"
        )

    try:
        ai = create_ai_service(profile)

        vulnerability = request.get("vulnerability", {})
        code_context = request.get("code_context", "")
        vulnerability_id = request.get("vulnerability_id")

        result = await ai.review_vulnerability(vulnerability, code_context)

        # 如果提供了 vulnerability_id 且审计成功，保存审计结果到数据库
        if vulnerability_id and not result.error:
            from sqlalchemy import select
            vuln_result = await db.execute(
                select(Vulnerability).where(Vulnerability.id == vulnerability_id)
            )
            vuln = vuln_result.scalar_one_or_none()
            if vuln:
                vuln.ai_assessment = {
                    "is_false_positive": result.is_false_positive,
                    "report": result.report,
                    "poc": result.poc,
                    "payload": result.payload,
                    "confidence": result.confidence,
                }
                await db.commit()

        return {
            "is_false_positive": result.is_false_positive,
            "report": result.report,
            "poc": result.poc,
            "payload": result.payload,
            "confidence": result.confidence,
            "error": result.error,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 审计失败: {str(e)}")


@router.post("/test")
async def test_ai_connection(db: AsyncSession = Depends(get_db)):
    """测试 AI 连接（使用当前激活的配置）"""
    config_model = await get_or_create_config(db)
    profile = get_active_profile_config(config_model)

    if not profile:
        raise HTTPException(status_code=400, detail="未配置 AI 服务")

    api_key = profile.get("apiKey") or profile.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置 API Key")

    try:
        ai = create_ai_service(profile)

        # 发送测试消息
        response = await ai.chat(session_id="test", message="Hello, this is a test.")
        return {"status": "success", "message": "AI 连接正常"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 连接失败: {str(e)}")


@router.post("/test-profile")
async def test_ai_connection_with_profile(request: dict):
    """
    测试 AI 连接（使用传入的临时配置）
    不保存到数据库，不影响当前激活配置
    """
    profile = request.get("profile")
    if not profile:
        raise HTTPException(status_code=400, detail="未提供配置信息")

    api_key = profile.get("apiKey") or profile.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置 API Key")

    base_url = profile.get("baseUrl") or profile.get("base_url")
    if not base_url:
        raise HTTPException(status_code=400, detail="未配置 API Base URL")

    try:
        ai = create_ai_service(profile)

        # 发送测试消息
        response = await ai.chat(session_id="test", message="Hello, this is a test.")
        return {"status": "success", "message": "AI 连接正常"}
    except Exception as e:
        logger.error(f"AI 连接测试失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI 连接失败: {str(e)}")
