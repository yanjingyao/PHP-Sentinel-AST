"""
设置路由
管理 AI 配置等设置
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Any, Dict

from database import get_db
from models import AIConfig

router = APIRouter(prefix="/api/settings", tags=["settings"])

# 默认 AI 配置
DEFAULT_AI_CONFIG = {
    "activeProfileId": "default-gemini",
    "profiles": [
        {"id": "default-gemini", "name": "内置 Gemini (默认)", "type": "gemini-builtin"}
    ],
}


@router.get("/{key}")
async def get_setting(key: str, db: AsyncSession = Depends(get_db)):
    """获取设置"""
    if key != "ai_config":
        raise HTTPException(status_code=404, detail="Setting not found")

    result = await db.execute(select(AIConfig).where(AIConfig.id == "default"))
    config = result.scalar_one_or_none()

    if not config:
        # 创建默认配置
        config = AIConfig(id="default", config=DEFAULT_AI_CONFIG)
        db.add(config)
        await db.commit()
        await db.refresh(config)

    return {
        "id": config.id,
        "config": config.config,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


@router.post("/")
async def create_or_update_setting(data: dict, db: AsyncSession = Depends(get_db)):
    """创建或更新设置"""
    key = data.get("key")
    value = data.get("value")

    if key != "ai_config":
        raise HTTPException(status_code=400, detail="Invalid setting key")

    result = await db.execute(select(AIConfig).where(AIConfig.id == "default"))
    config = result.scalar_one_or_none()

    if config:
        # 更新现有配置
        config.config = value
    else:
        # 创建新配置
        config = AIConfig(id="default", config=value)
        db.add(config)

    await db.commit()
    await db.refresh(config)

    return {
        "id": config.id,
        "config": config.config,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


@router.delete("/{key}")
async def delete_setting(key: str, db: AsyncSession = Depends(get_db)):
    """删除设置"""
    if key != "ai_config":
        raise HTTPException(status_code=404, detail="Setting not found")

    result = await db.execute(select(AIConfig).where(AIConfig.id == "default"))
    config = result.scalar_one_or_none()

    if config:
        await db.delete(config)
        await db.commit()

    return {"message": "Setting deleted"}
