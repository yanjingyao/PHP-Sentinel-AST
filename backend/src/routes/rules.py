"""
规则路由
管理自定义规则和规则状态
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import uuid

from database import get_db
from models import Rule
from schemas import RuleCreate, RuleResponse

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("/", response_model=List[RuleResponse])
async def get_all_rules(db: AsyncSession = Depends(get_db)):
    """获取所有自定义规则（非内置）"""
    result = await db.execute(select(Rule).where(Rule.is_built_in == False))
    rules = result.scalars().all()
    return rules


@router.post("/", response_model=RuleResponse)
async def create_rule(rule: RuleCreate, db: AsyncSession = Depends(get_db)):
    """创建新规则"""
    db_rule = Rule(
        id=str(uuid.uuid4()),
        name=rule.name,
        pattern=rule.pattern,
        type=rule.type,
        level=rule.level,
        enabled=rule.enabled,
        is_built_in=False,
        description=rule.description,
    )
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)
    return db_rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str, rule_update: RuleCreate, db: AsyncSession = Depends(get_db)
):
    """更新规则"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule.is_built_in:
        raise HTTPException(status_code=400, detail="Cannot modify built-in rules")

    rule.name = rule_update.name
    rule.pattern = rule_update.pattern
    rule.type = rule_update.type
    rule.level = rule_update.level
    rule.enabled = rule_update.enabled
    rule.description = rule_update.description

    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """删除规则"""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule.is_built_in:
        raise HTTPException(status_code=400, detail="Cannot delete built-in rules")

    await db.delete(rule)
    await db.commit()
    return {"message": "Rule deleted"}


@router.get("/states")
async def get_rule_states(db: AsyncSession = Depends(get_db)):
    """获取所有规则的启用状态"""
    result = await db.execute(select(Rule))
    rules = result.scalars().all()
    return {rule.id: rule.enabled for rule in rules}


@router.post("/states")
async def save_rule_state(data: dict, db: AsyncSession = Depends(get_db)):
    """保存规则状态"""
    rule_id = data.get("rule_id")
    enabled = data.get("enabled")

    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule:
        rule.enabled = enabled
        await db.commit()

    return {"rule_id": rule_id, "enabled": enabled}
