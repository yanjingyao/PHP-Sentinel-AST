"""
网络日志路由
管理 HTTP Proxy History
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List
import uuid
import httpx
import time

from database import get_db
from models import NetworkLog
from schemas import NetworkLogCreate, NetworkLogResponse, ProxyRequest, ProxyResponse

router = APIRouter(prefix="/api/network", tags=["network"])


@router.post("/proxy", response_model=ProxyResponse)
async def proxy_request(request: ProxyRequest):
    """
    后端代理请求
    用于解决前端 CORS 问题，并支持访问内网资源
    """
    start_time = time.time()

    # 过滤掉一些不安全的头部，防止干扰
    headers = request.headers or {}
    # Host header usually set automatically by client based on URL
    unsafe_headers = ["host", "content-length", "connection"]
    safe_headers = {}
    for k, v in headers.items():
        # Skip invalid header names (e.g., request line mistakenly passed as header)
        if k.lower() in unsafe_headers:
            continue
        # Header names cannot contain spaces or colons at start
        if " " in k or "\t" in k or "\n" in k or "\r" in k:
            continue
        safe_headers[k] = v

    try:
        # 使用 verify=False 允许自签名证书 (常见的测试场景)
        async with httpx.AsyncClient(timeout=request.timeout, verify=False) as client:
            response = await client.request(
                method=request.method,
                url=request.url,
                headers=safe_headers,
                content=request.body,
                follow_redirects=True,
            )

            duration = int((time.time() - start_time) * 1000)

            # 转换响应头
            res_headers = dict(response.headers)

            return ProxyResponse(
                status=response.status_code,
                status_text=response.reason_phrase,
                headers=res_headers,
                body=response.text,
                time=duration,
                size=len(response.content),
            )

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")


@router.get("/logs")
async def get_all_logs(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """获取所有网络日志（按时间倒序）"""
    result = await db.execute(
        select(NetworkLog).order_by(desc(NetworkLog.created_at)).limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": log.id,
            "method": log.method,
            "url": log.url,
            "request_headers": log.request_headers,
            "request_body": log.request_body,
            "response_status": log.response_status,
            "response_status_text": log.response_status_text,
            "response_headers": log.response_headers,
            "response_body": log.response_body,
            "duration": log.duration,
            "size": log.size,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]


@router.post("/logs", response_model=NetworkLogResponse)
async def create_log(
    log_data: NetworkLogCreate,
    db: AsyncSession = Depends(get_db),
):
    """创建新的网络日志"""
    log = NetworkLog(
        id=str(uuid.uuid4()),
        method=log_data.method,
        url=log_data.url,
        request_headers=log_data.request_headers,
        request_body=log_data.request_body,
        response_status=log_data.response_status,
        response_status_text=log_data.response_status_text,
        response_headers=log_data.response_headers,
        response_body=log_data.response_body,
        duration=log_data.duration,
        size=log_data.size,
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)
    return log


@router.delete("/logs/{log_id}")
async def delete_log(log_id: str, db: AsyncSession = Depends(get_db)):
    """删除单条日志"""
    result = await db.execute(select(NetworkLog).where(NetworkLog.id == log_id))
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    await db.delete(log)
    await db.commit()
    return {"message": "Log deleted"}


@router.delete("/logs")
async def clear_all_logs(db: AsyncSession = Depends(get_db)):
    """清空所有日志"""
    from sqlalchemy import delete

    await db.execute(delete(NetworkLog))
    await db.commit()
    return {"message": "All logs cleared"}
